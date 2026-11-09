-- Merge only an authenticated, automatically-created Feishu account into an
-- existing email account. Keep the source tombstone and conflict snapshots.
CREATE TABLE IF NOT EXISTS user_account_merges (
    source_user_id BIGINT PRIMARY KEY REFERENCES users(id),
    target_user_id BIGINT NOT NULL REFERENCES users(id),
    snapshot JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (source_user_id <> target_user_id)
);

CREATE OR REPLACE FUNCTION merge_feishu_account(source_id BIGINT, target_id BIGINT, issuer_key TEXT, open_id TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    source_user users%ROWTYPE;
    target_user users%ROWTYPE;
    item RECORD;
    saved JSONB;
    snapshots JSONB := '{}'::jsonb;
BEGIN
    IF source_id = target_id THEN RETURN; END IF;
    -- All merges lock in ID order; repeated callbacks cannot transfer balance twice.
    PERFORM id FROM users WHERE id IN (source_id, target_id) ORDER BY id FOR UPDATE;
    SELECT * INTO STRICT source_user FROM users WHERE id = source_id;
    SELECT * INTO STRICT target_user FROM users WHERE id = target_id;
    IF EXISTS (SELECT 1 FROM user_account_merges WHERE source_user_id = source_id AND target_user_id = target_id) THEN RETURN; END IF;
    IF source_user.deleted_at IS NOT NULL OR target_user.deleted_at IS NOT NULL
       OR source_user.status <> 'active' OR target_user.status <> 'active'
       OR source_user.role <> 'user' OR source_user.signup_source <> 'oidc'
       OR source_user.email NOT LIKE '%@oidc-connect.invalid'
       OR target_user.email LIKE '%@oidc-connect.invalid'
       OR NOT EXISTS (SELECT 1 FROM auth_identities WHERE user_id = source_id AND provider_type = 'oidc' AND provider_key = issuer_key AND provider_subject = open_id)
    THEN RAISE EXCEPTION 'Feishu account merge is not allowed'; END IF;
    -- Never silently replace a separately configured second factor or passkey.
    IF source_user.totp_enabled OR EXISTS (SELECT 1 FROM passkey_credentials WHERE user_id = source_id)
    THEN RAISE EXCEPTION 'Feishu account has additional authentication credentials'; END IF;

    snapshots := jsonb_build_object('source_user', to_jsonb(source_user) - 'password_hash' - 'totp_secret_encrypted');
    -- Keep the email account's preferences on collisions, with the original rows
    -- retained in the merge audit. Move non-conflicting settings below.
    FOR item IN SELECT * FROM (VALUES
        ('announcement_reads', 'announcement_id'),
        ('user_allowed_groups', 'group_id'),
        ('user_attribute_values', 'attribute_id'),
        ('user_group_rate_multipliers', 'group_id'),
        ('user_avatars', NULL),
        ('passkey_user_handles', NULL),
        ('promo_code_usages', 'promo_code_id'),
        ('orphan_allowed_groups_audit', 'group_id'),
        ('usage_dashboard_hourly_users', 'bucket_start'),
        ('usage_dashboard_daily_users', 'bucket_date')
    ) AS pairs(table_name, key_name) LOOP
        EXECUTE format('SELECT COALESCE(jsonb_agg(to_jsonb(s)), ''[]''::jsonb) FROM %I s WHERE s.user_id = $1', item.table_name) INTO saved USING source_id;
        snapshots := snapshots || jsonb_build_object(item.table_name, saved);
        EXECUTE format('DELETE FROM %I s WHERE s.user_id = $1 AND EXISTS (SELECT 1 FROM %I t WHERE t.user_id = $2 %s)',
            item.table_name, item.table_name,
            CASE WHEN item.key_name IS NULL THEN '' ELSE format('AND t.%I = s.%I', item.key_name, item.key_name) END)
            USING source_id, target_id;
    END LOOP;
    -- Preserve provider grant history without giving signup/first-bind rewards twice.
    DELETE FROM user_provider_default_grants s WHERE s.user_id = source_id AND EXISTS (
        SELECT 1 FROM user_provider_default_grants t WHERE t.user_id = target_id AND t.provider_type = s.provider_type AND t.grant_reason = s.grant_reason);

    SELECT COALESCE(jsonb_agg(to_jsonb(s)), '[]'::jsonb) INTO saved FROM user_subscriptions s WHERE user_id = source_id;
    snapshots := snapshots || jsonb_build_object('user_subscriptions', saved);
    UPDATE user_subscriptions t SET
        expires_at = GREATEST(t.expires_at, s.expires_at),
        daily_usage_usd = t.daily_usage_usd + s.daily_usage_usd,
        weekly_usage_usd = t.weekly_usage_usd + s.weekly_usage_usd,
        monthly_usage_usd = t.monthly_usage_usd + s.monthly_usage_usd
    FROM user_subscriptions s WHERE t.user_id = target_id AND s.user_id = source_id
        AND t.group_id = s.group_id AND t.deleted_at IS NULL AND s.deleted_at IS NULL;
    UPDATE user_subscriptions s SET deleted_at = NOW() WHERE s.user_id = source_id AND s.deleted_at IS NULL AND EXISTS (
        SELECT 1 FROM user_subscriptions t WHERE t.user_id = target_id AND t.group_id = s.group_id AND t.deleted_at IS NULL);
    SELECT COALESCE(jsonb_agg(to_jsonb(s)), '[]'::jsonb) INTO saved FROM user_platform_quotas s WHERE user_id = source_id;
    snapshots := snapshots || jsonb_build_object('user_platform_quotas', saved);
    UPDATE user_platform_quotas t SET
        daily_usage_usd = t.daily_usage_usd + s.daily_usage_usd,
        weekly_usage_usd = t.weekly_usage_usd + s.weekly_usage_usd,
        monthly_usage_usd = t.monthly_usage_usd + s.monthly_usage_usd
    FROM user_platform_quotas s WHERE t.user_id = target_id AND s.user_id = source_id
        AND t.platform = s.platform AND t.deleted_at IS NULL AND s.deleted_at IS NULL;
    UPDATE user_platform_quotas s SET deleted_at = NOW() WHERE s.user_id = source_id AND s.deleted_at IS NULL AND EXISTS (
        SELECT 1 FROM user_platform_quotas t WHERE t.user_id = target_id AND t.platform = s.platform AND t.deleted_at IS NULL);

    -- Move application-owned resources. Historical admin/security/monitor events
    -- retain their original actor IDs, resolvable through user_account_merges.
    FOR item IN SELECT unnest(ARRAY[
        'auth_identities','api_keys','usage_logs','billing_usage_entries',
        'batch_image_jobs','payment_orders','announcement_reads',
        'user_allowed_groups','user_attribute_values','user_group_rate_multipliers',
        'user_avatars','passkey_user_handles','promo_code_usages','orphan_allowed_groups_audit',
        'usage_dashboard_hourly_users','usage_dashboard_daily_users',
        'user_provider_default_grants','user_subscriptions','user_platform_quotas',
        'user_affiliate_ledger','gemini_cached_contents'
    ]) AS table_name LOOP
        EXECUTE format('UPDATE %I SET user_id = $1 WHERE user_id = $2', item.table_name) USING target_id, source_id;
    END LOOP;
    UPDATE redeem_codes SET used_by = target_id WHERE used_by = source_id;
    -- Keep both invitation codes valid; old referral ownership remains an audited
    -- historical record, while spendable referral balances belong to the target.
    UPDATE user_affiliates t SET aff_quota = t.aff_quota + s.aff_quota,
        aff_history_quota = t.aff_history_quota + s.aff_history_quota,
        aff_count = t.aff_count + s.aff_count
    FROM user_affiliates s WHERE t.user_id = target_id AND s.user_id = source_id;
    IF NOT EXISTS (SELECT 1 FROM user_affiliates WHERE user_id = target_id) THEN
        UPDATE user_affiliates SET user_id = target_id WHERE user_id = source_id;
    ELSE
        UPDATE user_affiliates SET aff_quota = 0, aff_history_quota = 0, aff_count = 0 WHERE user_id = source_id;
    END IF;
    UPDATE user_affiliates SET inviter_id = target_id WHERE inviter_id = source_id AND user_id <> target_id;
    UPDATE user_affiliate_ledger SET source_user_id = target_id WHERE source_user_id = source_id;
    UPDATE pending_auth_sessions SET target_user_id = target_id WHERE target_user_id = source_id;
    UPDATE users SET balance = balance + source_user.balance,
        frozen_balance = frozen_balance + source_user.frozen_balance, updated_at = NOW() WHERE id = target_id;
    INSERT INTO user_account_merges(source_user_id, target_user_id, snapshot) VALUES (source_id, target_id, snapshots);
    UPDATE users SET balance = 0, frozen_balance = 0, status = 'disabled', deleted_at = NOW(), updated_at = NOW() WHERE id = source_id;
END;
$$;

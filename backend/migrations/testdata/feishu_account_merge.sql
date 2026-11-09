\set ON_ERROR_STOP on
BEGIN;
-- Run inside BEGIN/ROLLBACK after loading 249_feishu_account_merge.sql.
DO $$
DECLARE
    source_id BIGINT := -925001;
    target_id BIGINT := -925002;
    group_id_test BIGINT := -925003;
BEGIN
    INSERT INTO users(id,email,password_hash,signup_source,balance,status,role)
      VALUES (source_id,'merge-test@oidc-connect.invalid','source-password','oidc',3.25,'active','user'),
             (target_id,'merge-test@example.invalid','email-password','email',7.5,'active','user');
    INSERT INTO groups(id,name) VALUES(group_id_test,'feishu-merge-test');
    INSERT INTO auth_identities(user_id,provider_type,provider_key,provider_subject)
      VALUES(source_id,'oidc','https://accounts.feishu.cn','ou_merge_test');
    INSERT INTO api_keys(id,user_id,key,name) VALUES(-925004,source_id,'feishu-merge-test-key','merge-test');
    INSERT INTO accounts(id,name,platform,type) VALUES(-925005,'feishu-merge-test','openai','apikey');
    INSERT INTO usage_logs(id,user_id,api_key_id,account_id,model,input_tokens,total_cost)
      VALUES(-925006,source_id,-925004,-925005,'merge-test',42,1.25);
    INSERT INTO user_allowed_groups(user_id,group_id) VALUES(source_id,group_id_test),(target_id,group_id_test);
    INSERT INTO user_subscriptions(user_id,group_id,starts_at,expires_at,daily_usage_usd)
      VALUES(source_id,group_id_test,NOW(),NOW()+INTERVAL '2 days',2),
            (target_id,group_id_test,NOW(),NOW()+INTERVAL '1 day',3);
    INSERT INTO user_platform_quotas(user_id,platform,daily_usage_usd)
      VALUES(source_id,'openai',2),(target_id,'openai',3);
    -- Invalid identity must fail without moving balance or keys.
    BEGIN
      PERFORM merge_feishu_account(source_id,target_id,'https://accounts.feishu.cn','wrong-subject');
      RAISE EXCEPTION 'invalid identity unexpectedly succeeded';
    EXCEPTION WHEN raise_exception THEN
      IF SQLERRM = 'invalid identity unexpectedly succeeded' THEN RAISE; END IF;
    END;
    IF (SELECT balance FROM users WHERE id=source_id) <> 3.25 THEN RAISE EXCEPTION 'failed merge changed balance'; END IF;
    -- A separately configured second factor must prevent silent consolidation.
    UPDATE users SET totp_enabled = TRUE WHERE id = source_id;
    BEGIN
      PERFORM merge_feishu_account(source_id,target_id,'https://accounts.feishu.cn','ou_merge_test');
      RAISE EXCEPTION '2FA source unexpectedly merged';
    EXCEPTION WHEN raise_exception THEN
      IF SQLERRM = '2FA source unexpectedly merged' THEN RAISE; END IF;
    END;
    IF (SELECT balance FROM users WHERE id=source_id) <> 3.25 THEN RAISE EXCEPTION 'rejected 2FA merge changed balance'; END IF;
    UPDATE users SET totp_enabled = FALSE WHERE id = source_id;
    PERFORM merge_feishu_account(source_id,target_id,'https://accounts.feishu.cn','ou_merge_test');
    PERFORM merge_feishu_account(source_id,target_id,'https://accounts.feishu.cn','ou_merge_test');
    IF (SELECT balance FROM users WHERE id=target_id) <> 10.75 THEN RAISE EXCEPTION 'balance not conserved/idempotent'; END IF;
    IF (SELECT password_hash FROM users WHERE id=target_id) <> 'email-password' THEN RAISE EXCEPTION 'email password changed'; END IF;
    IF (SELECT user_id FROM api_keys WHERE id=-925004) <> target_id THEN RAISE EXCEPTION 'key not migrated'; END IF;
    IF NOT EXISTS(SELECT 1 FROM usage_logs WHERE id=-925006 AND user_id=target_id AND input_tokens=42 AND total_cost=1.25) THEN RAISE EXCEPTION 'usage history not preserved'; END IF;
    IF NOT EXISTS(SELECT 1 FROM auth_identities WHERE user_id=target_id AND provider_subject='ou_merge_test') THEN RAISE EXCEPTION 'identity not migrated'; END IF;
    IF NOT EXISTS(SELECT 1 FROM users WHERE id=source_id AND balance=0 AND deleted_at IS NOT NULL AND status='disabled') THEN RAISE EXCEPTION 'source not archived'; END IF;
    IF (SELECT COUNT(*) FROM user_allowed_groups WHERE user_id=target_id AND group_id=group_id_test) <> 1 THEN RAISE EXCEPTION 'duplicate permissions'; END IF;
    IF (SELECT daily_usage_usd FROM user_subscriptions WHERE user_id=target_id AND group_id=group_id_test AND deleted_at IS NULL) <> 5 THEN RAISE EXCEPTION 'subscription usage not conserved'; END IF;
    IF (SELECT daily_usage_usd FROM user_platform_quotas WHERE user_id=target_id AND platform='openai' AND deleted_at IS NULL) <> 5 THEN RAISE EXCEPTION 'platform usage not conserved'; END IF;
    IF NOT EXISTS(SELECT 1 FROM user_account_merges WHERE source_user_id=source_id AND target_user_id=target_id) THEN RAISE EXCEPTION 'audit missing'; END IF;
END;
$$;

ROLLBACK;

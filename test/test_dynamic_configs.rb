# frozen_string_literal: true

require 'test_helper'

# Tests for #357: Dynamic per-record config overrides.
#
# REQUIREMENT: All module configs should be accessible via instance methods
# that delegate to self.class.config_name, allowing per-record overrides
# by overriding the instance method in the application model.
#
# Pattern (from session_limitable):
#   def max_active_sessions
#     self.class.max_active_sessions
#   end
# User can override:
#   def max_active_sessions
#     admin? ? 5 : 1
#   end
class TestDynamicConfigs < ActiveSupport::TestCase
  # ── SessionLimitable ─────────────────────────────────────────

  test 'SessionLimitable: max_active_sessions instance method delegates to class config' do
    user = User.new
    assert_equal User.max_active_sessions, user.max_active_sessions
  end

  test 'SessionLimitable: reject_sessions instance method delegates to class config' do
    user = User.new
    assert_equal User.reject_sessions, user.reject_sessions
  end

  test 'SessionLimitable: timeout_in instance method delegates to class config' do
    user = User.new
    assert_equal User.timeout_in, user.timeout_in
  end

  # ── SessionTraceable ─────────────────────────────────────────

  test 'SessionTraceable: session_ip_verification instance method delegates to class config' do
    user = TraceableUser.new
    assert_equal TraceableUser.session_ip_verification, user.session_ip_verification
  end

  # ── Expirable ──────────────────────────────────────────────────

  test 'Expirable: expire_after instance method delegates to class config' do
    user = User.new
    assert_equal User.expire_after, user.expire_after
  end

  test 'Expirable: delete_expired_after instance method delegates to class config' do
    user = User.new
    assert_equal User.delete_expired_after, user.delete_expired_after
  end

  test 'Expirable: last_activity_update_interval instance method delegates to class config' do
    user = User.new
    assert_equal User.last_activity_update_interval, user.last_activity_update_interval
  end

  test 'Expirable: expired? uses instance method (overridable)' do
    user = User.new(last_activity_at: 10.days.ago)

    # With default expire_after (90 days), 10 days ago is NOT expired
    assert_not user.expired?

    # Override to 5 days — now it IS expired
    user.define_singleton_method(:expire_after) { 5.days }
    assert user.expired?
  end

  # ── ParanoidVerification ───────────────────────────────────────

  test 'ParanoidVerification: paranoid_code_regenerate_after_attempt instance method delegates to class config' do
    user = User.new
    assert_equal User.paranoid_code_regenerate_after_attempt, user.paranoid_code_regenerate_after_attempt
  end

  test 'ParanoidVerification: verification_code_generator instance method delegates to class config' do
    user = User.new
    assert_equal User.verification_code_generator, user.verification_code_generator
  end

  test 'ParanoidVerification: paranoid_attempts_remaining uses instance method (overridable)' do
    user = User.new(paranoid_verification_code: 'abcde', paranoid_verification_attempt: 0)

    # Default: 10 attempts
    assert_equal 10, user.paranoid_attempts_remaining

    # Override to 3 — remaining should be 3
    user.define_singleton_method(:paranoid_code_regenerate_after_attempt) { 3 }
    assert_equal 3, user.paranoid_attempts_remaining
  end

  test 'ParanoidVerification: verify_code uses instance method for regenerate threshold' do
    user = User.create!(
      email: 'dynamic_config@example.com',
      password: 'passWord1',
      paranoid_verification_code: 'abcde',
      paranoid_verification_attempt: 0
    )

    # Override threshold to 2
    user.define_singleton_method(:paranoid_code_regenerate_after_attempt) { 2 }

    user.verify_code('wrong')
    assert_equal 1, user.paranoid_verification_attempt
    assert_equal 'abcde', user.paranoid_verification_code

    # Second wrong attempt triggers regeneration (threshold=2)
    user.verify_code('wrong-again')
    assert_equal 0, user.paranoid_verification_attempt
    assert_not_equal 'abcde', user.paranoid_verification_code
  end

  test 'ParanoidVerification: generate_paranoid_code uses instance method for generator' do
    user = User.new

    # Override generator to return fixed code
    user.define_singleton_method(:verification_code_generator) { -> { 'FIXED' } }
    user.generate_paranoid_code

    assert_equal 'FIXED', user.paranoid_verification_code
  end

  # ── PasswordArchivable (already dynamic — verify) ─────────────

  test 'PasswordArchivable: deny_old_passwords instance method exists and delegates' do
    user = User.new
    assert_equal User.deny_old_passwords, user.deny_old_passwords
  end

  test 'PasswordArchivable: archive_count instance method exists and delegates' do
    user = User.new
    assert_equal User.password_archiving_count, user.archive_count
  end

  # ── PasswordExpirable (already dynamic — verify) ──────────────

  test 'PasswordExpirable: expire_password_after instance method exists and delegates' do
    user = User.new
    assert_equal User.expire_password_after, user.expire_password_after
  end

  # ── SecureValidatable ─────────────────────────────────────────

  test 'SecureValidatable: allow_passwords_equal_to_email instance method delegates to class config' do
    user = User.new
    assert_equal User.allow_passwords_equal_to_email, user.allow_passwords_equal_to_email
  end

  test 'SecureValidatable: email_validation instance method delegates to class config' do
    user = User.new
    assert_equal User.email_validation, user.email_validation
  end

  test 'SecureValidatable: password_complexity instance method delegates to class config' do
    user = User.new
    assert_equal User.password_complexity, user.password_complexity
  end

  test 'SecureValidatable: password_complexity_validator instance method delegates to class config' do
    user = User.new
    assert_equal User.password_complexity_validator, user.password_complexity_validator
  end

  test 'SecureValidatable: password_length instance method delegates to class config' do
    user = User.new
    assert_equal User.password_length, user.password_length
  end

  test 'SecureValidatable: email_not_equal_password_validation uses instance method (overridable)' do
    user = User.new(email: 'test@example.com', password: 'test@example.com')

    # Default: allow_passwords_equal_to_email is false, so validation fails
    user.valid?
    assert user.errors[:password].any? { |msg| msg.include?('equal') || msg.include?('email') },
           'Expected password-equals-email validation error'

    # Override to allow it
    user.define_singleton_method(:allow_passwords_equal_to_email) { true }
    user.errors.clear
    user.send(:email_not_equal_password_validation)
    assert_not user.errors[:password].any? { |msg| msg.include?('equal') || msg.include?('email') },
               'Expected no password-equals-email error when overridden'
  end
end

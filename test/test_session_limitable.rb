# frozen_string_literal: true

require 'test_helper'

class TestSessionLimitable < ActiveSupport::TestCase
  include ActiveSupport::Testing::TimeHelpers

  class ModifiedUser < User
    def skip_session_limitable?
      true
    end
  end

  test 'should have required_fields array' do
    assert_equal %i[unique_session_id max_active_sessions reject_sessions timeout_in], Devise::Models::SessionLimitable.required_fields(User)
  end

  test 'check is not skipped by default' do
    user = build(:user)

    assert_not(user.skip_session_limitable?)
  end

  test 'default check can be overridden by record instance' do
    modified_user = ModifiedUser.new(email: generate_unique_email, password: 'Password1')

    assert_predicate(modified_user, :skip_session_limitable?)
  end

  class SessionLimitableUser < User
    devise :session_limitable
    include ::Mongoid::Mappings if DEVISE_ORM == :mongoid
  end

  test 'includes Devise::Models::Compatibility' do
    assert_kind_of(Devise::Models::Compatibility, SessionLimitableUser.new)
  end

  test '#update_unique_session_id!(value) updates valid record' do
    user = create(:user)

    assert_predicate user, :persisted?
    assert_nil user.unique_session_id
    user.update_unique_session_id!('unique_value')
    user.reload

    assert_equal('unique_value', user.unique_session_id)
  end

  test '#update_unique_session_id!(value) updates invalid record atomically' do
    user = create(:user)
    original_email = user.email

    assert_predicate user, :persisted?
    user.email = ''

    assert_predicate user, :invalid?
    assert_nil user.unique_session_id
    user.update_unique_session_id!('unique_value')
    user.reload

    assert_equal(original_email, user.email)
    assert_equal('unique_value', user.unique_session_id)
  end

  test '#update_unique_session_id!(value) updates updated_at timestamp' do
    user = create(:user)
    original_updated_at = user.updated_at

    travel 2.seconds do
      user.update_unique_session_id!('unique_value')
      user.reload

      assert_operator user.updated_at, :>, original_updated_at, 'updated_at should advance when unique_session_id is set'
    end
  end

  test '#update_unique_session_id!(value) raises an exception on an unpersisted record' do
    user = build(:user)

    assert_not user.persisted?
    assert_raises(Devise::Models::Compatibility::NotPersistedError) { user.update_unique_session_id!('unique_value') }
  end

  test '#allow_limitable_authentication? returns true' do
    user = new_user

    assert_predicate user, :allow_limitable_authentication?
  end

  test '#deactivate_expired_sessions! returns true' do
    user = new_user

    assert user.deactivate_expired_sessions!
  end

  test '#max_active_sessions returns 1 regardless of config' do
    swap Devise, max_active_sessions: 10 do
      user = new_user

      assert_equal 1, user.max_active_sessions
    end
  end

  test '#reject_sessions? returns false regardless of config' do
    swap Devise, reject_sessions: true do
      user = new_user

      assert_not user.reject_sessions?
    end
  end

  test '#evict_oldest_session! returns false' do
    user = new_user

    assert_not user.evict_oldest_session!
  end
end

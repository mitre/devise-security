# frozen_string_literal: true

require_relative 'compatibility'
require 'devise-security/hooks/session_limitable'

module Devise
  module Models
    # SessionLimited ensures, that there is only one session usable per account at once.
    # If someone logs in, and some other is logging in with the same credentials,
    # the session from the first one is invalidated and not usable anymore.
    # The first one is redirected to the sign page with a message, telling that
    # someone used his credentials to sign in.
    #
    module SessionLimitable
      extend ActiveSupport::Concern
      include Devise::Models::Compatibility

      def self.required_fields(_klass)
        %i[unique_session_id max_active_sessions reject_sessions timeout_in]
      end

      # Update the unique_session_id on the model.  This will be checked in
      # the Warden after_set_user hook in {file:devise-security/hooks/session_limitable}
      # @param unique_session_id [String]
      # @return [void]
      # @raise [Devise::Models::Compatibility::NotPersistedError] if record is unsaved
      def update_unique_session_id!(unique_session_id)
        raise Devise::Models::Compatibility::NotPersistedError, 'cannot update a new record' unless persisted?

        attrs = { unique_session_id: unique_session_id }
        attrs[:updated_at] = Time.current if respond_to?(:updated_at)
        self.class.where(id: id).update_all(attrs)
        Rails.logger.debug { "[devise-security][session_limitable] unique_session_id=#{unique_session_id}" }
      end

      # Check whether the user is allowed to authenticate based on active session count.
      # Always returns +true+ (original behavior). Reserved for future session tracking.
      #
      # @return [Boolean] true if authentication should be allowed
      def allow_limitable_authentication?
        true
      end

      # Evict the oldest active session to make room for a new one.
      # Reserved for future session tracking.
      #
      # @return [Boolean] false (no-op without session tracking)
      def evict_oldest_session!
        false
      end

      # Deactivate sessions that have timed out based on +timeout_in+.
      # Reserved for future session tracking.
      #
      # @return [Boolean] true (no-op without session tracking)
      def deactivate_expired_sessions!
        true
      end

      # Maximum number of active sessions allowed.
      # Returns 1 (original behavior). Reserved for future session tracking.
      #
      # @return [Integer]
      def max_active_sessions
        1
      end

      # Whether to reject new sessions when at capacity (vs evicting oldest).
      # Returns false (original behavior). Reserved for future session tracking.
      #
      # @return [Boolean]
      def reject_sessions
        false
      end
      alias reject_sessions? reject_sessions

      # Session timeout duration.
      # Supports +Proc+ values — resolved via +instance_exec+.
      #
      # @return [ActiveSupport::Duration, nil] session timeout duration
      def timeout_in
        value = self.class.timeout_in
        value.is_a?(Proc) ? instance_exec(&value) : value
      end

      # Should session_limitable be skipped for this instance?
      # @return [Boolean]
      # @return [false] by default. This can be overridden by application logic as necessary.
      def skip_session_limitable?
        false
      end

      class_methods do
        ::Devise::Models.config(
          self,
          :max_active_sessions,
          :reject_sessions,
          :timeout_in
        )
      end
    end
  end
end

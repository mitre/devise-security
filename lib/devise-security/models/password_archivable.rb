# frozen_string_literal: true

require_relative 'compatibility'
require_relative "#{DEVISE_ORM}/old_password"

module Devise
  module Models
    # PasswordArchivable prevents password reuse by archiving old passwords.
    # Each password change stores the previous encrypted password in an
    # +OldPassword+ record. On validation, the new password is checked against
    # the most recent archived passwords.
    #
    # == Configuration
    # * +deny_old_passwords+ - +Integer+ count of old passwords to deny,
    #   +true+ to deny all archived, or +false+ to disable (default: +false+)
    # * +password_archiving_count+ - max number of old passwords to store
    #
    # @see OldPassword the model storing archived password hashes
    # @see Devise::Models::DatabaseAuthenticatable required base module
    module PasswordArchivable
      extend ActiveSupport::Concern
      include Devise::Models::Compatibility
      include Devise::Models::DatabaseAuthenticatable

      included do
        has_many :old_passwords, class_name: 'OldPassword', as: :password_archivable, dependent: :destroy
        before_update :archive_password, if: :will_save_change_to_encrypted_password?
        validate :validate_password_archive, if: :password_present?
      end

      delegate :present?, to: :password, prefix: true

      # @param _klass [Class] the model class including this module
      # @return [Array<Symbol>] required database columns (none for this module)
      def self.required_fields(_klass)
        []
      end

      # Add a validation error if the new password matches a previously used one.
      # @return [void]
      def validate_password_archive
        errors.add(:password, :taken_in_past) if will_save_change_to_encrypted_password? && password_archive_included?
      end

      # @return [Integer] max number of old passwords to store and check
      def max_old_passwords
        case deny_old_passwords
        when true
          [1, archive_count].max
        when false
          0
        else
          deny_old_passwords.to_i
        end
      end

      # Check if the new password matches any previously used password.
      # Compares against the most recent +max_old_passwords+ entries plus
      # the current (about to be replaced) encrypted password.
      #
      # @return [true] if the new password was used previously
      # @return [false] if reuse checking is disabled or no match found
      def password_archive_included?
        return false unless max_old_passwords.positive?

        old_passwords_including_cur_change = old_passwords.reorder(created_at: :desc).limit(max_old_passwords).pluck(:encrypted_password)
        old_passwords_including_cur_change << encrypted_password_was # include most recent change in list, but don't save it yet!
        old_passwords_including_cur_change.any? do |old_password|
          # NOTE: we deliberately do not do mass assignment here so that users that
          #   rely on `protected_attributes_continued` gem can still use this extension.
          #   See issue #68
          self.class.new.tap { |object| object.encrypted_password = old_password }.valid_password?(password)
        end
      end

      # Maximum number of old passwords to deny reuse of.
      # Override in your model for per-record dynamic behavior.
      # Supports +Proc+ values — resolved via +instance_exec+ so the Proc
      # has access to the model instance (e.g., for role-based logic).
      #
      # @return [Integer, Boolean] count, +true+ (deny all), or +false+ (allow all)
      def deny_old_passwords
        value = self.class.deny_old_passwords
        value.is_a?(Proc) ? instance_exec(&value) : value
      end

      # Set the deny_old_passwords config on the class.
      #
      # @param count [Integer, Boolean]
      def deny_old_passwords=(count)
        self.class.deny_old_passwords = count
      end

      # Number of old passwords to archive.
      # Override in your model for per-record dynamic behavior.
      # Supports +Proc+ values — resolved via +instance_exec+.
      #
      # @return [Integer]
      def archive_count
        value = self.class.password_archiving_count
        value.is_a?(Proc) ? instance_exec(&value) : value
      end

      private

      # Archive the current encrypted password before save and prune excess entries.
      # When archiving is disabled (+max_old_passwords+ is 0), destroys all archives.
      #
      # @note Checks for an existing archive entry to avoid duplicates caused by
      #   Mongoid re-triggering callbacks when adding an old password.
      # @return [void]
      def archive_password
        if max_old_passwords.positive?
          return true if old_passwords.where(encrypted_password: encrypted_password_was).exists?

          old_passwords.create!(encrypted_password: encrypted_password_was) if encrypted_password_was.present?
          old_passwords.reorder(created_at: :desc).offset(max_old_passwords).destroy_all
        else
          old_passwords.destroy_all
        end
      end

      class_methods do
        ::Devise::Models.config(self, :password_archiving_count, :deny_old_passwords)
      end
    end
  end
end

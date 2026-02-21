# frozen_string_literal: true

require_relative 'compatibility'
require_relative '../validators/password_complexity_validator'

module Devise
  module Models
    # SecureValidatable provides stricter validations than Devise's built-in
    # +:validatable+ module. When both are present, SecureValidatable defers
    # presence/length/uniqueness checks to +:validatable+ and only adds the
    # extra security validations.
    #
    # Validations applied:
    # - Email format via +EmailValidator+ (when +email_validation+ is truthy)
    # - Email uniqueness scoped to +authentication_keys+
    # - Password complexity via configurable validator class
    # - Password != current password (on update)
    # - Password != email (unless +allow_passwords_equal_to_email+ is set)
    # - Password presence, confirmation, and length (unless +:validatable+ handles them)
    #
    # == Options
    #
    # SecureValidatable adds the following options to +devise_for+:
    #
    #   * +email_validation+: enable/disable email format validation
    #   * +password_length+: a +Range+ expressing password length. Defaults from Devise
    #   * +password_complexity+: a +Hash+ of options passed to the complexity validator
    #   * +password_complexity_validator+: validator class name (+String+ or +Class+).
    #     Defaults to {DeviseSecurity::PasswordComplexityValidator}
    #   * +allow_passwords_equal_to_email+: when truthy, skips the password-vs-email check
    #
    module SecureValidatable
      include Devise::Models::Compatibility

      def self.included(base)
        base.extend ClassMethods
        assert_secure_validations_api!(base)

        base.class_eval do
          already_validated_email = false

          # validate login in a strict way if not yet validated
          unless uniqueness_validation_of_login?
            validation_condition = "#{login_attribute}_changed?".to_sym

            validates login_attribute, uniqueness: {
                                         scope: secondary_authentication_keys,
                                         case_sensitive: !!case_insensitive_keys
                                       },
                                       if: validation_condition

            already_validated_email = login_attribute.to_s == 'email'
          end

          unless devise_validation_enabled?
            validates :email, presence: true, if: :email_required?
            validates :email, uniqueness: true, allow_blank: true, if: :email_changed? && :validate_email_uniqueness? unless already_validated_email

            validates_presence_of :password, if: :password_required?
            validates_confirmation_of :password, if: :password_required?

            validate if: :password_required? do |record|
              validates_with ActiveModel::Validations::LengthValidator,
                             attributes: :password,
                             allow_blank: true,
                             in: record.password_length
            end
          end

          # Extra email format validation via an external EmailValidator class.
          # Requires a gem that provides EmailValidator (e.g., rails_email_validator).
          # Set `config.email_validation = false` to disable.
          # See https://github.com/devise-security/devise-security/blob/main/README.md#e-mail-validation
          validate do
            if email_validation
              unless defined?(::EmailValidator)
                raise <<~MSG.squish
                  devise-security: email_validation is enabled but no EmailValidator class
                  was found. Install an email validator gem (e.g., 'rails_email_validator')
                  or set `config.email_validation = false` in your Devise initializer.
                  See: https://github.com/devise-security/devise-security#e-mail-validation
                MSG
              end
              validates_with(::EmailValidator, { attributes: :email })
            end
          end

          validate if: :password_required? do |record|
            validates_with(
              record.password_complexity_validator.is_a?(Class) ? record.password_complexity_validator : record.password_complexity_validator.classify.constantize,
              { attributes: :password }.merge(record.password_complexity)
            )
          end

          # don't allow use same password
          validate :current_equal_password_validation

          # don't allow email to equal password
          validate :email_not_equal_password_validation
        end
      end

      # Verify that the including class supports ActiveModel validations.
      #
      # @param base [Class] the class including this module
      # @raise [RuntimeError] if +base+ does not respond to +validates+
      # @return [void]
      def self.assert_secure_validations_api!(base)
        raise "Could not use SecureValidatable on #{base}" unless base.respond_to?(:validates)
      end

      # @param _klass [Class]
      # @return [Array<Symbol>] required database fields (none for this module)
      def self.required_fields(_klass)
        []
      end

      # Validate that the new password is not the same as the current password.
      # Skipped for new records, when the encrypted password hasn't changed,
      # or when the password is blank. Creates a temporary model instance with
      # the old encrypted password to test via +valid_password?+.
      #
      # @return [void]
      def current_equal_password_validation
        return if new_record? || !will_save_change_to_encrypted_password? || password.blank?

        dummy = self.class.new(encrypted_password: encrypted_password_was).tap do |user|
          user.password_salt = password_salt_was if respond_to?(:password_salt)
        end
        errors.add(:password, :equal_to_current_password) if dummy.valid_password?(password)
      end

      # Validate that the password does not match the user's email address.
      # Comparison is case-insensitive and stripped of whitespace.
      # Skipped when +allow_passwords_equal_to_email+ is truthy, when either
      # field is blank, or on existing records with no password change.
      #
      # @return [void]
      def email_not_equal_password_validation
        return if allow_passwords_equal_to_email

        return if password.blank? || email.blank? || (!new_record? && !will_save_change_to_encrypted_password?)

        return unless Devise.secure_compare(password.downcase.strip, email.downcase.strip)

        errors.add(:password, :equal_to_email)
      end

      protected

      # Checks whether a password is needed or not. For validations only.
      # Passwords are always required if it's a new record, or if the password
      # or confirmation are being set somewhere.
      #
      # @return [Boolean]
      def password_required?
        !persisted? || !password.nil? || !password_confirmation.nil?
      end

      # Whether an email address is required for validation.
      #
      # @return [Boolean] true by default; override to make email optional
      def email_required?
        true
      end

      # Whether email uniqueness should be validated.
      #
      # @return [Boolean] true by default; override to skip uniqueness check
      def validate_email_uniqueness?
        true
      end

      # Delegate configuration accessors to the class so instance-level
      # validations can read class-level Devise config values.
      delegate(
        :allow_passwords_equal_to_email,
        :email_validation,
        :password_complexity,
        :password_complexity_validator,
        :password_length,
        to: :class
      )

      module ClassMethods
        Devise::Models.config(
          self,
          :allow_passwords_equal_to_email,
          :email_validation,
          :password_complexity,
          :password_complexity_validator,
          :password_length
        )

        private

        # Check if the login attribute already has a uniqueness validator registered
        # (e.g., from the application model or another Devise module).
        #
        # @return [Boolean]
        def uniqueness_validation_of_login?
          validators.any? do |validator|
            validator_orm_klass = DEVISE_ORM == :active_record ? ActiveRecord::Validations::UniquenessValidator : ::Mongoid::Validatable::UniquenessValidator
            validator.is_a?(validator_orm_klass) && validator.attributes.include?(login_attribute)
          end
        end

        # The primary authentication key (first element of +authentication_keys+).
        # Handles both Array and Hash configurations of +authentication_keys+,
        # consistent with how Devise core normalizes keys in its strategies
        # and failure app.
        #
        # @return [Symbol]
        # @raise [RuntimeError] if +authentication_keys+ is empty
        def login_attribute
          keys = authentication_keys.respond_to?(:keys) ? authentication_keys.keys : authentication_keys
          raise "#{self} has no authentication_keys configured. Cannot apply SecureValidatable." if keys.empty?

          keys.first
        end

        # All authentication keys except the primary one, used as the
        # +scope+ for uniqueness validation. Normalizes Hash-style keys.
        #
        # @return [Array<Symbol>]
        def secondary_authentication_keys
          keys = authentication_keys.respond_to?(:keys) ? authentication_keys.keys : authentication_keys
          keys[1..]
        end

        # Whether Devise's built-in +:validatable+ module is already included.
        # When true, SecureValidatable skips presence/length/uniqueness checks
        # to avoid duplicate validations.
        #
        # @return [Boolean]
        def devise_validation_enabled?
          ancestors.map(&:to_s).include? 'Devise::Models::Validatable'
        end
      end
    end
  end
end

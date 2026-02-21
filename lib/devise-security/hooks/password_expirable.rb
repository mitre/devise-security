# frozen_string_literal: true

# Warden hook for the +PasswordExpirable+ module.
#
# After authentication, checks whether the user's password has expired
# and stores the result in the Warden session for the controller to act on.
#
# @see Devise::Models::PasswordExpirable
# @see DeviseSecurity::Controllers::Helpers#handle_password_change
Warden::Manager.after_authentication do |record, warden, options|
  if record.respond_to?(:need_change_password?)
    scope = options[:scope]
    expired = record.need_change_password?
    warden.session(scope)['password_expired'] = expired
    if expired
      Rails.logger.debug { "[devise-security][password_expirable] password expired for #{record.class}##{record.id}" }
    end
  end
end

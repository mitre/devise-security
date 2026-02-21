# frozen_string_literal: true

module Devise
  module Models
    # SecurityQuestionable provides an accessible alternative to CAPTCHAs
    # for screenreader-compatible authentication flows. Users select a
    # security question at registration and answer it on sensitive forms
    # (unlock, password reset, confirmation).
    #
    # == Form Setup
    # Add to unlock, password, and confirmation forms:
    #   text_field_tag :security_question_answer
    #   text_field_tag :captcha
    #
    # Add to registration/edit forms:
    #   f.select :security_question_id, SecurityQuestion.where(locale: I18n.locale).map { |s| [s.name, s.id] }
    #   f.text_field :security_question_answer
    #
    # @see SecurityQuestion the model storing available questions per locale
    # @see Devise::Models::DatabaseAuthenticatable required base module
    module SecurityQuestionable
      extend ActiveSupport::Concern

      # @param _klass [Class] the model class including this module
      # @return [Array<Symbol>] required database columns
      def self.required_fields(_klass)
        [:security_question_id, :security_question_answer]
      end
    end
  end
end

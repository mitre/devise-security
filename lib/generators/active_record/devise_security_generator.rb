# frozen_string_literal: true

require_relative '../devise_security/migration_generator'

# nodoc
module ActiveRecord
  module Generators
    # Generator migration for DeviseSecurity
    # Usage:
    #  rails generate active_record:devise_security
    class DeviseSecurityGenerator < ::DeviseSecurity::MigrationGenerator
      source_root File.expand_path('templates', __dir__)

      def create_migration_file
        # No standalone migrations needed; use per-module generators instead.
        # e.g., rails generate devise_security:session_limitable
      end
    end
  end
end

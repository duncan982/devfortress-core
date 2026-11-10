# frozen_string_literal: true

require "openssl"
require "securerandom"

module DevFortress
  # Shared AES-256-GCM reversible-encryption primitive.
  #
  # Mirrors packages/devfortress-sdk/src/credential-vault.ts. A generic
  # reversible-encryption primitive; ApiKeyAliasingService and
  # tier2_gated/identity_projection.rb each wire into their own
  # alias-keyed stores.
  #
  # Key derivation: HKDF-SHA256 with a zero salt and a namespaced info
  # string, matching tier2_gated/alias_generator.rb's hkdf_alias.
  module CredentialVault
    VaultEncryptedRecord = Struct.new(:ciphertext, :iv, :auth_tag, keyword_init: true)

    # Derive a 32-byte AES-256 key from an application secret + context via
    # HKDF-SHA256.
    def self.derive_vault_key(application_secret, context)
      info = "devfortress.credential-vault.#{context}"
      OpenSSL::KDF.hkdf(application_secret.to_s.b, salt: "\x00".b * 32, info: info.b, length: 32, hash: "SHA256")
    end

    # Pure primitive: encrypt a real credential with an explicit key.
    def self.encrypt(real_credential, key)
      iv = SecureRandom.random_bytes(12)
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv
      ciphertext = cipher.update(real_credential.to_s.b) + cipher.final
      VaultEncryptedRecord.new(
        ciphertext: ciphertext.unpack1("H*"),
        iv: iv.unpack1("H*"),
        auth_tag: cipher.auth_tag.unpack1("H*"),
      )
    end

    # Pure primitive: decrypt a ciphertext bundle with an explicit key.
    # Raises OpenSSL::Cipher::CipherError (does not return garbage
    # plaintext) on auth-tag mismatch.
    def self.decrypt(record, key)
      decipher = OpenSSL::Cipher.new("aes-256-gcm")
      decipher.decrypt
      decipher.key = key
      decipher.iv = [record.iv].pack("H*")
      decipher.auth_tag = [record.auth_tag].pack("H*")
      decipher.update([record.ciphertext].pack("H*")) + decipher.final
    end
  end

  # A self-contained, in-memory vault instance: encrypts + stores real
  # credentials under an alias, later resolves the alias back to plaintext.
  # Used wherever a class needs its own alias-keyed encrypted store.
  class CredentialVaultStore
    MAX_TRACKED_RECORDS = 50_000

    def initialize(max_entries = MAX_TRACKED_RECORDS)
      @max_entries = max_entries
      @store = {}
    end

    def register(alias_id, real_credential, key)
      record = CredentialVault.encrypt(real_credential, key)
      if @store.key?(alias_id)
        @store.delete(alias_id)
      elsif @store.size >= @max_entries && !@store.empty?
        @store.delete(@store.first[0])
      end
      @store[alias_id] = { record: record, key: key }
      record
    end

    # Raises on auth-tag mismatch (does not return garbage plaintext) —
    # matches the Node primitive's #resolve, which does not rescue.
    def resolve(alias_id)
      stored = @store[alias_id]
      return nil unless stored

      CredentialVault.decrypt(stored[:record], stored[:key])
    end

    def revoke(alias_id)
      !@store.delete(alias_id).nil?
    end

    def has?(alias_id)
      @store.key?(alias_id)
    end
  end
end

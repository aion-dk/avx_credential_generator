require 'openssl'
require 'securerandom'

module Crypto

  CURVE = OpenSSL::PKey::EC.new('secp256k1')
  ALPHABET = '2346789ABCDEFGHJKLMNPQRTUVWXYZabcdefghijkmnpqrstuvwxyz'.split('')
  ELECTION_CODE_LENGTH = 14

  class << self

    # Verifies a schnorr signature
    #
    # @param message String with message
    # @param signature_string String with 2 comma separated hex numbers
    # @param public_key_string String with public key
    # @return a boolean
    def verify_schnorr_signature(message, signature_string, public_key_string)
      schnorr_signature = Crypto::SchnorrSignature.from_s(signature_string)
      public_key = hex_to_point public_key_string

      schnorr_signature.verify(message, public_key)
    rescue => _
      # In case of any error (fx. malformed parameters) we return false
      false
    end

    # Generates a schnorr signature
    # Signs a message
    #
    # @param message String with message
    # @param private_key_string String with private key
    # @return String the signature as a String
    def generate_schnorr_signature(message, private_key_string)
      private_key = hex_to_bn(private_key_string)
      schnorr_signature = Crypto::SchnorrSignature.sign(message, private_key)

      schnorr_signature.to_s
    end

    # Generates a key pair as voter credential
    #
    # @return two Strings the private key and the public key
    def generate_key_pair()
      private_key = random_bn(CURVE.group.order)
      public_key = CURVE.group.generator.mul(private_key)

      [bn_to_hex(private_key), point_to_hex(public_key)]
    end

    def generate_credential_pair
      begin
        election_code = Array.new(ELECTION_CODE_LENGTH){ ALPHABET[SecureRandom.random_number(ALPHABET.size)] }.join
        hash = Digest::SHA256.hexdigest(election_code)
        private_key = hex_to_bn(hash)
      end while private_key != private_key % CURVE.group.order
      public_key = CURVE.group.generator.mul(private_key)

      [election_code, point_to_hex(public_key)]
    end

    def election_code_to_private_key(election_code)
      hash = Digest::SHA256.hexdigest(election_code)
      private_key = hex_to_bn(hash) % CURVE.group.order

      bn_to_hex(private_key)
    end

    def election_code_to_public_key(election_code)
      hash = Digest::SHA256.hexdigest(election_code)
      private_key = hex_to_bn(hash) % CURVE.group.order
      public_key = CURVE.group.generator.mul(private_key)

      point_to_hex(public_key)
    end

    # Adds public keys together
    # Used for computing the encryption key out of all trustee public keys
    #
    # @param public_keys_string Array of String with all public keys
    # @return Strings the resulting point as a string
    def aggregate_public_keys(public_keys_string)
      points = public_keys_string.map{ |point_string| hex_to_point point_string }

      result = infinity_point
      points.each{ |point| result = add_points(result, point) }

      point_to_hex result
    end

    # Generates an empty cryptogram that voters can use to encrypt their vote on top
    #
    # @return two Strings the cryptogram as a comma separated String and the random value as a String
    def generate_empty_cryptogram(public_key_string)
      public_key = hex_to_point public_key_string
      randomness = random_bn(CURVE.group.order)
      cryptogram = Crypto::ElGamalPointCryptogram.encrypt(infinity_point, public_key, randomness)

      [cryptogram.to_s, bn_to_hex(randomness)]
    end

    # Generates the commitment of a non-interactive discrete logarithm multiple proof
    # Used for proving an empty cryptogram to a voter
    #
    # @param encryption_key_string String with encryption key value
    # @param secret_string String with the private key value
    # @return two Strings the commitment point as a String and the commitment scalar as a String
    def generate_commitment_for_empty_cryptogram_proof(encryption_key_string, secret_string)
      encryption_key = hex_to_point encryption_key_string
      generators = [CURVE.group.generator, encryption_key]
      secret = hex_to_bn(secret_string)

      (commitment_point, commitment_scalar) = Crypto::DiscreteLogarithmMultipleProof.generate_commitment(generators, secret)

      [point_to_hex(commitment_point), bn_to_hex(commitment_scalar)]
    end

    # Computes the response of a non-interactive discrete logarithm multiple proof
    # Used for proving an empty cryptogram to a voter
    #
    # @param commitment_scalar_string String with the commitment scalar values
    # @param challenge_string String with the challenge values
    # @param secret_string String with the secret value
    # @return String the response value as a String
    def compute_response_for_empty_cryptogram_proof(commitment_scalar_string, challenge_string, secret_string)
      commitment_scalar = hex_to_bn(commitment_scalar_string)
      challenge = hex_to_bn(challenge_string)
      secret = hex_to_bn(secret_string)

      response = Crypto::DiscreteLogarithmMultipleProof.compute_response(commitment_scalar, challenge, secret)

      bn_to_hex(response)
    end

    # Verifies the proof of correct encryption
    # Used for verifying that the empty cryptogram has been used for encrypting vote
    #
    # @param proof_string String with the proof value
    # @param randomness_string String with the randomness value of the empty cryptogram
    # @param cryptogram_string String with the new cryptogram value
    # @return a boolean
    def verify_use_of_empty_cryptogram(proof_string, randomness_string, cryptogram_string)
      proof = Crypto::DiscreteLogarithmProof.from_s(proof_string)
      randomness = hex_to_bn(randomness_string)
      randomness_point = CURVE.group.generator.mul(randomness)
      cryptogram = Crypto::ElGamalPointCryptogram.from_s(cryptogram_string)
      point = Crypto.add_points( cryptogram.randomness, randomness_point.invert!)

      proof.verify(CURVE.group.generator, point)
    end

    # Computes the public share of the decryption key of a trustee
    # Used for verifying a partial decryption
    #
    # @param id integer the id of the trustee
    # @param coefficients_string_with_degrees Array of tuples [coefficient, degree] with all coefficients of all
    # trustees in hex format together with their degree. Public keys are also coefficients but with degree 0.
    # @return String the public share as a string
    def compute_public_share_of_decryption_key(id, coefficients_string_with_degrees)
      id_bn = OpenSSL::BN.new(id)
      public_share = infinity_point
      coefficients_string_with_degrees.each do |coefficient_string, degree|
        coefficient = hex_to_point coefficient_string
        exponent = id_bn.mod_exp(OpenSSL::BN.new(degree), CURVE.group.order)
        public_share = add_points(public_share, coefficient.mul(exponent))
      end

      point_to_hex public_share
    end

    # Computes the partial secret share of the decryption key of a trustee by computing the polynomial function.
    # Used for generating partial secrets by the system trustee
    #
    # @param id integer the id of the trustee (receiver)
    # @param secret_coefficients_string_with_degrees Array of tuples [secret_coefficient, degree] with all secret
    # coefficients of this trustee (system trustee) in hex format together with their degree. The private key is also
    # a secret coefficient but with degree 0.
    # @return String the partial secret share as a string
    def compute_polynomial(id, secret_coefficients_string_with_degrees)
      id_bn = OpenSSL::BN.new(id)
      partial_secret_share = OpenSSL::BN.new(0)
      secret_coefficients_string_with_degrees.each do |coefficient_string, degree|
        coefficient = hex_to_bn(coefficient_string)
        exponent = id_bn.mod_exp(OpenSSL::BN.new(degree), CURVE.group.order)
        partial_secret_share = (partial_secret_share + (coefficient * exponent)) % CURVE.group.order
      end

      bn_to_hex(partial_secret_share)
    end

    # Encrypts a scalar by generating an ElGamalScalarCryptogram.
    # Used for generating partial secrets by the system trustee
    #
    # @param partial_secret_string string The scalar to be encrypted in hex format
    # @param encryption_key_string string The encryption key in hex format
    # @return String the final cryptogram as a string
    def encrypt_partial_secret(partial_secret_string, encryption_key_string)
      partial_secret = hex_to_bn(partial_secret_string)
      encryption_key = hex_to_point encryption_key_string

      cryptogram = Crypto::ElGamalScalarCryptogram.encrypt(partial_secret, encryption_key, random_bn)

      cryptogram.to_s
    end

    # Decrypts an ElGamalScalarCryptogram.
    # Used for decrypting the partial secrets of the system trustee received from all the other trustees.
    #
    # @param encrypted_partial_secret_string string The cryptogram to be decrypted in hex format
    # @param decryption_key_string string The private key of the trustee in hex format
    # @return String the final partial secret (scalar) as a string
    def decrypt_partial_secret(encrypted_partial_secret_string, decryption_key_string)
      cryptogram = Crypto::ElGamalScalarCryptogram.from_s(encrypted_partial_secret_string)
      decryption_key = hex_to_bn(decryption_key_string)

      partial_secret = cryptogram.decrypt(decryption_key)

      bn_to_hex(partial_secret)
    end




    # TODO documentation
    def validate_partial_secret(partial_secret_share_string, id, coefficients_string_with_degrees)
      id_bn = OpenSSL::BN.new(id)
      partial_secret_share = hex_to_bn(partial_secret_share_string)
      partial_public_share = infinity_point

      coefficients_string_with_degrees.each do |coefficient_string, degree|
        coefficient = hex_to_point coefficient_string
        exponent = id_bn.mod_exp(OpenSSL::BN.new(degree), CURVE.group.order)
        partial_public_share = add_points(partial_public_share, coefficient.mul(exponent))
      end

      partial_public_share == CURVE.group.generator.mul(partial_secret_share)
    end




    # TODO documentation
    def aggregate_partial_secrets(partial_secrets_string)
      secret_share = OpenSSL::BN.new(0)

      partial_secrets_string.each do |partial_secret_string|
        partial_secret_share = hex_to_bn(partial_secret_string)
        secret_share = secret_share + partial_secret_share
      end
      secret_share = secret_share % CURVE.group.order

      bn_to_hex(secret_share)
    end

    # Computes the threshold decryption coefficient of a trustee (lambda)
    # Used for aggregating partial decryptions
    #
    # @param id integer the id of the trustee
    # @param other_ids Array of integers The ids of all the other trustees participating in decryption
    # @return String the value of lambda coefficient as a string
    def compute_lambda(id, other_ids)
      id_bn = OpenSSL::BN.new(id)
      other_ids_bn = other_ids.map{ |other_id| OpenSSL::BN.new(other_id) }

      i = id_bn
      lambda = OpenSSL::BN.new(1)
      other_ids_bn.each do |j|
        lambda = (lambda * (-j) * (i - j).mod_inverse(CURVE.group.order)) % CURVE.group.order
      end
      lambda = lambda + CURVE.group.order if lambda.negative?

      bn_to_hex(lambda)
    end

    # Interprets a point as a vote
    # Used for decoding votes after decryption phase
    # Detect invalid vote encodings
    #
    # @param point_string String with the point encoding the vote value
    # @return an integer defining the type of encoding used and the value of the vote (can be a string or an arrays od ids)
    def decode_vote_from_point(point_string)
      point = hex_to_point(point_string)

      # blank vote
      return :blank if point.infinity?


      point_string = point_to_hex(point)
      vote_encoding_type = point_string[2*1, 2*1].to_i(16)
      vote_hex = point_string[2*2, 2*30]

      case vote_encoding_type
        when 1
          encoding_type = :text
          vote = vote_hex.scan(/../).map{ |x| x.hex.chr }.join
        when 2
          encoding_type = :ids
          vote = vote_hex.scan(/../).map{ |x| x.to_i(16) }
        else
          raise 'point does not have a valid vote encoding'
      end

      [encoding_type, vote]
    end

    # Encodes a vote into a point
    # Used for encoding votes for encryption phase
    #
    # @param vote_encode_type integer representing the encoding type
    # (0 for blank vote, 1 for encoding of text, 2 for encoding of array of ids)
    # @param vote String or Array of ids with the value of the vote
    # @return String the value of the point encoding the vote, as string
    def encode_vote_to_point(vote_encode_type, vote)
      return infinity_point if vote_encode_type == :blank

      flag_byte = SecureRandom.random_number(2) == 0 ? '02' : '03'
      suffix_byte = '00'
      case vote_encode_type
        when :text
          encoding_type_byte = '01'
          vote_bytes = vote.each_byte.map{ |b| b.to_s(16) }.join
          padding_bytes = Array.new(30 - vote_bytes.length / 2) { |i| '00' }.join

          point_encoding = flag_byte + encoding_type_byte + vote_bytes + padding_bytes + suffix_byte
          point_bn = OpenSSL::BN.new(point_encoding, 16)
          found = false
          begin
            point = OpenSSL::PKey::EC::Point.new(CURVE.group, point_bn)
            found = true if point.on_curve?
          rescue
            point_bn = point_bn + OpenSSL::BN.new(1)
          end until found

        when :ids
          encoding_type_byte = '02'
          vote_bytes = vote.map{ |i| '%02x' % i }.join
          padding_bytes = Array.new(30 - vote_bytes.length / 2) { |i| '00' }.join

          point_encoding = flag_byte + encoding_type_byte + vote_bytes + padding_bytes + suffix_byte
          point_bn = OpenSSL::BN.new(point_encoding, 16)
          found = false
          begin
            point = OpenSSL::PKey::EC::Point.new(CURVE.group, point_bn)
            found = true if point.on_curve?
          rescue
            point_bn = point_bn + OpenSSL::BN.new(1)
          end until found

        else
          raise 'vote encoding not supported'
      end

      point
    end




    # Generates a random point
    #
    # @return (OpenSSL::PKey::EC::Point) a random point
    def random_point
      secp256k1_curve_prime = OpenSSL::BN.new('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f', 16)
      flag_byte = SecureRandom.random_number(2) == 0 ? '02' : '03'

      found = false
      begin
        x = random_bn(secp256k1_curve_prime)
        point_encoding = flag_byte + x.to_s(16)
        point_bn = OpenSSL::BN.new(point_encoding, 16)
        point = OpenSSL::PKey::EC::Point.new(CURVE.group, point_bn)
        found = point.on_curve?
      rescue
      end until found

      point
    end

    # Adds two points
    #
    # @param point_1 (OpenSSL::PKey::EC::Point) The first point
    # @param point_2 (OpenSSL::PKey::EC::Point) The second point
    # @return (OpenSSL::PKey::EC::Point) the resulted point
    def add_points(point_1, point_2)
      point_1.mul([OpenSSL::BN.new(1), OpenSSL::BN.new(1)], [point_2])
    end

    # Generates a random bn
    #
    # @param max (OpenSSL::BN) The maximum value.
    # @return (OpenSSL::BN) a random big num
    def random_bn(max = CURVE.group.order)
      OpenSSL::BN.new(SecureRandom.random_bytes(max.num_bytes), 2) % max
    end

    # Decodes a hex string representation of a point
    #
    # @param point_string String the hex string
    # @return (OpenSSL::PKey::EC::Point) the point
    def hex_to_point(point_string)
      if point_string == '00' or point_string == '0' or point_string == ''
        # point = infinity_point
        point = OpenSSL::PKey::EC::Point.new(CURVE.group)
      else
        point = OpenSSL::PKey::EC::Point.new(CURVE.group, OpenSSL::BN.new(point_string, 16))
      end

      point
    end

    # Encodes point as hex string
    #
    # @param point (OpenSSL::PKey::EC::Point) the point
    # @return String the hex string
    def point_to_hex(point)
      bn = point.to_bn(:compressed)
      return '00' if bn.zero?

      bn.to_s(16).downcase
    end

    # Get the infinity point O
    #
    # @return (OpenSSL::PKey::EC::Point) the infinity point
    def infinity_point
      OpenSSL::PKey::EC::Point.new(CURVE.group)
    end

    # Decodes a hex string representation of a big num
    #
    # @param hex_string String the hex string
    # @return (OpenSSL::BN) the big num
    def hex_to_bn(hex_string)
      OpenSSL::BN.new(hex_string, 16)
    end

    # Encodes a big num as hex string
    #
    # @param bn (OpenSSL::BN) the big num
    # @return String the hex string
    def bn_to_hex(bn)
      bn.to_s(16).downcase.rjust(32 * 2, '0')
    end





    # USED FOR TESTING
    # METHODS THAT ARE NORMALLY RUN IN JS

    # Multiplies the curve generator with the scalar.
    # Computes the public key based on a private key.
    #
    # @param scalar (String) the value of the scalar
    # @return String the hex string of the computed point
    def G_times(scalar)
      scalar_bn = hex_to_bn(scalar)
      point = CURVE.group.generator.mul(scalar_bn)

      point_to_hex point
    end

    # Verifies the proof of empty cryptograms
    #
    # @param proof_string String with the proof value
    # @param empty_cryptogram_string String with the empty cryptogram
    # @param encryption_key_string String with the encryption key
    # @return a boolean
    def verify_empty_cryptogram_proof(proof_string, empty_cryptogram_string, encryption_key_string)
      dlm_proof = DiscreteLogarithmMultipleProof.from_s(proof_string)
      empty_cryptogram = ElGamalPointCryptogram.from_s(empty_cryptogram_string)
      encryption_key = hex_to_point(encryption_key_string)

      generators = [CURVE.group.generator, encryption_key]
      points = [empty_cryptogram.randomness, empty_cryptogram.ciphertext]

      dlm_proof.verify_without_challenge(generators, points)
    end

    # Adds two cryptograms together homomorphically
    #
    # @param c1 The first cryptogram
    # @param c2 The second cryptogram
    # @return the resulted cryptogram
    def homomorphically_add_cryptograms(c1, c2)
      randomness = add_points(c1.randomness, c2.randomness)
      ciphertext = add_points(c1.ciphertext, c2.ciphertext)

      ElGamalPointCryptogram.new(randomness, ciphertext)
    end

    # Encrypts vote by generating a vote cryptogram
    #
    # @param vote_string String with the vote value encoded as a point
    # @param empty_cryptogram_string String with the empty cryptogram
    # @param encryption_key_string String with the encryption key
    # @return a the final vote cryptogram and value of the randomizer
    def encrypt_vote (vote_string, empty_cryptogram_string, encryption_key_string)
      vote = hex_to_point vote_string
      empty_cryptogram = ElGamalPointCryptogram.from_s empty_cryptogram_string
      encryption_key = hex_to_point encryption_key_string

      randomness = random_bn
      vote_cryptogram = ElGamalPointCryptogram.encrypt(vote, encryption_key, randomness)
      final_cryptogram = homomorphically_add_cryptograms(empty_cryptogram, vote_cryptogram)

      [final_cryptogram.to_s, bn_to_hex(randomness)]
    end

    # Generates a random point
    #
    # @return (String) a random point in hex format
    def random_point_hex
      point_to_hex random_point
    end

    def random_bn_hex
      bn_to_hex(random_bn)
    end

    # Generates a discrete logarithm proof
    # Used for proving the correct encryption (proving the use of the empty cryptogram)
    #
    # @param secret_string The private key of the proof as a string
    # @return the proof as a string
    def generate_discrete_logarithm_proof (secret_string)
      secret = hex_to_bn(secret_string)

      proof = Crypto::DiscreteLogarithmProof.generate(CURVE.group.generator, secret)
      proof.to_s
    end

    def combine_public_keys(point_hex_1, point_hex_2)
      point_1 = hex_to_point(point_hex_1)
      point_2 = hex_to_point(point_hex_2)

      point_sum = add_points(point_1, point_2)
      point_to_hex(point_sum)
    end

  end
end

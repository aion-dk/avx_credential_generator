module Crypto


  # Instances of this class represent Discrete Logarithm Equality Proofs,
  # which are simply a tuple of two points named `commitment_1` and 'commitment_2' and two integers `challenge` and 'response'.
  class DiscreteLogarithmEqualityProof
    # @return (OpenSSL::PKey::EC::Point)
    attr_reader :commitment_1
    # @return (OpenSSL::PKey::EC::Point)
    attr_reader :commitment_2
    # @return (OpenSSL::BN)
    attr_reader :challenge
    # @return (OpenSSL::BN)
    attr_reader :response

    # @param commitment_1 (OpenSSL::PKey::EC::Point) the value of the first commitment.
    # @param commitment_2 (OpenSSL::PKey::EC::Point) the value of the second commitment.
    # @param challenge (OpenSSL::BN) the value of the challenge.
    # @param response (OpenSSL::BN) the value of the response.
    def initialize(commitment_1, commitment_2, challenge, response)
      @commitment_1, @commitment_2, @challenge, @response = commitment_1, commitment_2, challenge, response

      (commitment_1.is_a?(OpenSSL::PKey::EC::Point) &&
          commitment_1.on_curve?) or raise ArgumentError, 'first commitment is not a valid point.'

      (commitment_2.is_a?(OpenSSL::PKey::EC::Point) &&
          commitment_2.on_curve?) or raise ArgumentError, 'second commitment is not a valid point.'

      (challenge.is_a?(OpenSSL::BN) &&
          challenge == challenge % CURVE.group.order) or raise ArgumentError, 'challenge is not a valid integer.'

      (response.is_a?(OpenSSL::BN) &&
          response == response % CURVE.group.order) or raise ArgumentError, 'response is not a valid integer.'
    end

    # Instantiates an {DiscreteLogarithmEqualityProof} from a given string
    #
    # @param string (String) The encoded string.
    # @return (DiscreteLogarithmProof) a new discrete logarithm equality proof
    def self.from_s(string)
      strings = string.split(',')

      case strings.length
      when 4
        commitment_1_point = Crypto.hex_to_point strings[0]
        commitment_2_point = Crypto.hex_to_point strings[1]
        challenge_bn = Crypto.hex_to_bn(strings[2])
        response_bn = Crypto.hex_to_bn(strings[3])
      else
        raise ArgumentError, 'invalid number of arguments in encoding.'
      end

      DiscreteLogarithmEqualityProof.new(commitment_1_point, commitment_2_point, challenge_bn, response_bn)
    end

    # Generates a non-interactive discrete logarithm equality proof
    #
    # @param generator_1 (OpenSSL::PKey::EC::Point) the values of the first generator.
    # @param generator_2 (OpenSSL::PKey::EC::Point) the values of the second generator.
    # @param private_key (OpenSSL::BN) the value of the key.
    # @return (DiscreteLogarithmEqualityProof) a new discrete logarithm equality proof
    def self.generate(generator_1, generator_2, private_key)
      commitment_scalar = Crypto.random_bn(CURVE.group.order)
      commitment_point_1 = generator_1.mul(commitment_scalar)
      commitment_point_2 = generator_2.mul(commitment_scalar)
      public_key_1 = generator_1.mul(private_key)
      public_key_2 = generator_2.mul(private_key)

      hash_string =
          generator_1.to_octet_string(:compressed) +
              generator_2.to_octet_string(:compressed) +
              commitment_point_1.to_octet_string(:compressed) +
              commitment_point_2.to_octet_string(:compressed) +
              public_key_1.to_octet_string(:compressed) +
              public_key_2.to_octet_string(:compressed)
      hash = Digest::SHA256.hexdigest(hash_string)
      challenge = Crypto.hex_to_bn(hash) % CURVE.group.order

      response = (commitment_scalar + (challenge * private_key)) % CURVE.group.order

      DiscreteLogarithmEqualityProof.new(commitment_point_1, commitment_point_2, challenge, response)
    end

    # Verifies the {DiscreteLogarithmEqualityProof} and returns true if valid
    # Verifies that the challenge is computed non-interactively
    #
    # @param generator_1 (OpenSSL::PKey::EC::Point) the value of the first generator.
    # @param generator_2 (OpenSSL::PKey::EC::Point) the value of the second generator.
    # @param public_key_1 (OpenSSL::PKey::EC::Point) the value of the first public key.
    # @param public_key_2 (OpenSSL::PKey::EC::Point) the value of the second public key.
    def verify(generator_1, generator_2, public_key_1, public_key_2)
      if verify_without_challenge(generator_1, generator_2, public_key_1, public_key_2)
        hash_string =
            generator_1.to_octet_string(:compressed) +
            generator_2.to_octet_string(:compressed) +
            @commitment_1.to_octet_string(:compressed) +
            @commitment_2.to_octet_string(:compressed) +
            public_key_1.to_octet_string(:compressed) +
            public_key_2.to_octet_string(:compressed)
        hash = Digest::SHA256.hexdigest(hash_string)

        if @challenge == Crypto.hex_to_bn(hash) % CURVE.group.order
          return true
        end
      end

      false
    end

    # Verifies the {DiscreteLogarithmEqualityProof} and returns true if valid
    # Does not verify how challenge was computed
    #
    # @param generator_1 (OpenSSL::PKey::EC::Point) the value of the first generator.
    # @param generator_2 (OpenSSL::PKey::EC::Point) the value of the second generator.
    # @param public_key_1 (OpenSSL::PKey::EC::Point) the value of the first public key.
    # @param public_key_2 (OpenSSL::PKey::EC::Point) the value of the second public key.
    def verify_without_challenge(generator_1, generator_2, public_key_1, public_key_2)
      left_hand_side_1 = generator_1.mul(response)
      # right_hand_side_1 = commitment_1 * 1 + public_key_1 * challenge
      right_hand_side_1 = @commitment_1.mul([OpenSSL::BN.new(1), @challenge], [public_key_1])

      left_hand_side_2 = generator_2.mul(response)
      # right_hand_side_2 = commitment_2 * 1 + public_key_2 * challenge
      right_hand_side_2 = @commitment_2.mul([OpenSSL::BN.new(1), @challenge], [public_key_2])

      left_hand_side_1 == right_hand_side_1 && left_hand_side_2 == right_hand_side_2
    end

    # Outputs the proof as a string with all values encoded as hex, concatenated by a comma
    #
    # @return (String) The encoded proof.
    def to_s()
      Crypto.point_to_hex(@commitment_1) + ',' + Crypto.point_to_hex(@commitment_2) + ',' + Crypto.bn_to_hex(@challenge) + ',' + Crypto.bn_to_hex(@response)
    end
  end

end
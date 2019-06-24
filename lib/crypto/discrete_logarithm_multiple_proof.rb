module Crypto



# Instances of this class represent Discrete Logarithm Multiple Proofs,
# which are simply a tuple of a points named `commitment` and two integers `challenge` and 'response'.
class DiscreteLogarithmMultipleProof
  # @return (OpenSSL::PKey::EC::Point)
  attr_reader :commitment
  # @return (OpenSSL::BN)
  attr_reader :challenge
  # @return (OpenSSL::BN)
  attr_reader :response

  # @param commitment (OpenSSL::PKey::EC::Point) the value of the commitment.
  # @param challenge (OpenSSL::BN) the value of the challenge.
  # @param response (OpenSSL::BN) the value of the response.
  def initialize(commitment, challenge, response)
    @commitment, @challenge, @response = commitment, challenge, response

    (commitment.is_a?(OpenSSL::PKey::EC::Point) &&
        commitment.on_curve?) or raise ArgumentError, 'commitment is not a valid point.'

    (challenge.is_a?(OpenSSL::BN) &&
        challenge == challenge % CURVE.group.order) or raise ArgumentError, 'challenge is not a valid integer.'

    (response.is_a?(OpenSSL::BN) &&
        response == response % CURVE.group.order) or raise ArgumentError, 'response is not a valid integer.'
  end

  # Instantiates an {DiscreteLogarithmMultipleProof} from a given string
  #
  # @param string (String) The encoded string.
  # @return (DiscreteLogarithmProof) a new discrete logarithm proof
  def self.from_s(string)
    strings = string.split(',')

    case strings.length
    when 3
      commitment_point = Crypto.hex_to_point strings[0]
      challenge_bn = Crypto.hex_to_bn(strings[1])
      response_bn = Crypto.hex_to_bn(strings[2])
    else
      raise ArgumentError, 'invalid number of arguments in encoding.'
    end

    DiscreteLogarithmMultipleProof.new(commitment_point, challenge_bn, response_bn)
  end

  # Generates a non-interactive discrete logarithm multiple proof
  #
  # @param generators (Array of OpenSSL::PKey::EC::Point) the 'n'+1 values of the generators.
  # @param private_key (OpenSSL::BN) the value of the key.
  # @return (DiscreteLogarithmMultipleProof) a new discrete logarithm multiple proof
  def self.generate(generators, private_key)
    n = generators.length - 1

    commitment_scalar = Crypto.random_bn(CURVE.group.order)
    public_keys = Array.new(n + 1) { |i| generators[i].mul(private_key) }

    hash_string = ''
    public_keys.each{ |public_key| hash_string += public_key.to_octet_string(:compressed) }
    hash = Digest::SHA256.digest(hash_string)
    h = hash

    z = Array.new(n)
    for i in 1..n
      hash_string = i.to_s + h
      hash = Digest::SHA256.hexdigest(hash_string)
      z[i-1] = Crypto.hex_to_bn(hash) % CURVE.group.order
    end

    commitment = generators[0]
    for i in 0..n-1
      # commitment = commitment * 1 + generator[i+1] * z[i]
      commitment = commitment.mul([OpenSSL::BN.new(1), z[i]], [generators[i+1]])
    end
    commitment = commitment.mul(commitment_scalar)

    hash_string = ''
    generators.each{ |generator| hash_string += generator.to_octet_string(:compressed) }
    hash_string += commitment.to_octet_string(:compressed)
    public_keys.each{ |public_key| hash_string += public_key.to_octet_string(:compressed) }
    hash = Digest::SHA256.hexdigest(hash_string)
    challenge = Crypto.hex_to_bn(hash) % CURVE.group.order

    response = (commitment_scalar + (challenge * private_key)) % CURVE.group.order

    DiscreteLogarithmMultipleProof.new(commitment, challenge, response)
  end

  # Generates the commitment for a interactive discrete logarithm multiple proof
  #
  # @param generators (Array of OpenSSL::PKey::EC::Point) the 'n'+1 values of the generators.
  # @param private_key (OpenSSL::BN) the value of the key.
  # @return (OpenSSL::PKey::EC::Point, OpenSSL::BN) two values: the commitment point and the commitment scalar
  def self.generate_commitment(generators, private_key)
    n = generators.length - 1

    commitment_scalar = Crypto.random_bn(CURVE.group.order)
    public_keys = Array.new(n + 1) { |i| generators[i].mul(private_key) }

    hash_string = ''
    public_keys.each{ |public_key| hash_string += public_key.to_octet_string(:compressed) }
    hash = Digest::SHA256.digest(hash_string)
    h = hash

    z = Array.new(n)
    for i in 1..n
      hash_string = i.to_s + h
      hash = Digest::SHA256.hexdigest(hash_string)
      z[i-1] = Crypto.hex_to_bn(hash) % CURVE.group.order
    end

    commitment = generators[0]
    for i in 0..n-1
      # commitment = commitment * 1 + generator[i+1] * z[i]
      commitment = commitment.mul([OpenSSL::BN.new(1), z[i]], [generators[i+1]])
    end
    commitment = commitment.mul(commitment_scalar)

    [commitment, commitment_scalar]
  end

  # Computes the response for a interactive discrete logarithm multiple proof
  #
  # @param commitment_scalar (OpenSSL::BN) the value of the commitment scalar.
  # @param challenge (OpenSSL::BN) the value of the challenge.
  # @param private_key (OpenSSL::BN) the value of the key.
  # @return (OpenSSL::BN) the value of the response
  def self.compute_response(commitment_scalar, challenge, private_key)
    (commitment_scalar + (challenge * private_key)) % CURVE.group.order
  end

  # Verifies the {DiscreteLogarithmMultipleProof} and returns true if valid
  # Verifies that the challenge is computed non-interactively
  #
  # @param generators (Array of OpenSSL::PKey::EC::Point) the value of the generators.
  # @param public_keys (Array of OpenSSL::PKey::EC::Point) the value of the public keys.
  def verify(generators, public_keys)
    if verify_without_challenge(generators, public_keys)
      hash_string = ''
      generators.each{ |generator| hash_string += generator.to_octet_string(:compressed) }
      hash_string += @commitment.to_octet_string(:compressed)
      public_keys.each{ |public_key| hash_string += public_key.to_octet_string(:compressed) }
      hash = Digest::SHA256.hexdigest(hash_string)

      if @challenge == Crypto.hex_to_bn(hash) % CURVE.group.order
        return true
      end
    end

    false
  end

  # Verifies the {DiscreteLogarithmMultipleProof} and returns true if valid
  # Does not verify how challenge was computed
  #
  # @param generators (Array of OpenSSL::PKey::EC::Point) the value of the generators.
  # @param public_keys (Array of OpenSSL::PKey::EC::Point) the value of the public keys.
  def verify_without_challenge(generators, public_keys)
    return false if generators.length != public_keys.length

    n = generators.length - 1

    hash_string = ''
    public_keys.each{ |public_key| hash_string += public_key.to_octet_string(:compressed) }
    hash = Digest::SHA256.digest(hash_string)
    h = hash

    z = Array.new(n)
    for i in 1..n
      hash_string = i.to_s + h
      hash = Digest::SHA256.hexdigest(hash_string)
      z[i-1] = Crypto.hex_to_bn(hash) % CURVE.group.order
    end

    left_hand_side = generators[0]
    for i in 0..n-1
      # left_hand_side = left_hand_side * 1 + generator[i+1] * z[i]
      left_hand_side = left_hand_side.mul([OpenSSL::BN.new(1), z[i]], [generators[i+1]])
    end
    left_hand_side = left_hand_side.mul(@response)

    right_hand_side = public_keys[0]
    for i in 0..n-1
      # right_hand_side = right_hand_side * 1 + public_keys[i+1] * z[i]
      right_hand_side = right_hand_side.mul([OpenSSL::BN.new(1), z[i]], [public_keys[i+1]])
    end
    # right_hand_side = commitment * 1 + right_hand_side * challenge
    right_hand_side = @commitment.mul([OpenSSL::BN.new(1), @challenge], [right_hand_side])

    left_hand_side == right_hand_side
  end

  # Outputs the proof as a string with all values encoded as hex, concatenated by a comma
  #
  # @return (String) The encoded proof.
  def to_s()
    Crypto.point_to_hex(@commitment) + ',' + Crypto.bn_to_hex(@challenge) + ',' + Crypto.bn_to_hex(@response)
  end
end

end

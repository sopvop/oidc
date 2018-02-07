module OIDC.Crypto.RNG
    ( RNG
    , newRNG
    , randomBytes
    ) where


import           Crypto.Random   (ChaChaDRG, drgNew, randomBytesGenerate)
import           Data.ByteString (ByteString)
import           Data.IORef      (IORef, atomicModifyIORef', newIORef)
import           Data.Tuple      (swap)

-- | Thread safe ChaCha DRG
newtype RNG = RNG (IORef ChaChaDRG)

-- | Create new DRG from system entropy
newRNG :: IO RNG
newRNG = drgNew >>= fmap RNG . newIORef

withRNG :: RNG -> (ChaChaDRG -> (a, ChaChaDRG)) -> IO a
withRNG (RNG g) f = atomicModifyIORef' g $ swap . f

-- | Generate n random bytes
randomBytes :: Int -> RNG -> IO ByteString
randomBytes n r = withRNG r (randomBytesGenerate n)


module OIDC.Crypto.RNG
    ( RNG
    , newRNG
    , randomBytes
    , runDRG
    , withRNG
    ) where


import           Crypto.Random
    (ChaChaDRG, MonadPseudoRandom, drgNew, randomBytesGenerate, withDRG)
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

runDRG :: RNG -> MonadPseudoRandom ChaChaDRG a -> IO a
runDRG rng act = withRNG rng $ flip withDRG act

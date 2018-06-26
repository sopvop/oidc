module OIDC.Server.ClientStore.Memory
  ( initClientStore
  ) where

import           Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as HashMap
import           Data.IORef (IORef, newIORef, readIORef)

import           OIDC.Server.ClientStore (ClientStore (..))
import           OIDC.Types (ClientAuth (..), ClientId (..))

newtype MemoryClientStore = MemoryClientStore
  { unMemoryClientStore :: IORef (HashMap ClientId ClientAuth)
  }

mcsLookupClientById :: MemoryClientStore -> ClientId -> IO (Maybe ClientAuth)
mcsLookupClientById s cid =
    HashMap.lookup cid <$> readIORef (unMemoryClientStore s)

initClientStore :: [ClientAuth] -> IO ClientStore
initClientStore initial = do
    ref <- newIORef hm
    let ms = MemoryClientStore ref
    pure $ ClientStore (mcsLookupClientById ms)
  where
    hm = HashMap.fromList $ map (\x -> (clientId x,x)) initial

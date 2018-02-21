module Main where

import           Test.Tasty
    (defaultMain, testGroup)

import qualified Tests.OIDC.Crypto.Jwt
import qualified Tests.OIDC.Crypto.Message
import           Tests.OIDC.Server.Store.Memory.UserStore
import qualified Tests.OIDC.Types.Email

main :: IO ()
main = defaultMain $ testGroup "OIDC"
   [ Tests.OIDC.Crypto.Jwt.testTree
   , Tests.OIDC.Crypto.Message.testTree
   , Tests.OIDC.Server.Store.Memory.UserStore.testTree
   , Tests.OIDC.Types.Email.testTree
   ]

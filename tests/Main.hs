module Main where

import           Test.Tasty                (defaultMain, testGroup)

import qualified Tests.OIDC.Crypto.Message
import qualified Tests.OIDC.Types.Email

main :: IO ()
main = defaultMain $ testGroup "OIDC"
   [ Tests.OIDC.Crypto.Message.testTree
   , Tests.OIDC.Types.Email.testTree
   ]

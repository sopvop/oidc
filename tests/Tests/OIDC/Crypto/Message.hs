{-# LANGUAGE OverloadedStrings #-}
module Tests.OIDC.Crypto.Message
  ( testTree
  ) where

import           Control.Monad.IO.Class       (liftIO)

import           Test.QuickCheck.Monadic
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck

import           Crypto.Cipher.ChaChaPoly1305 (nonce12)
import           Crypto.Error                 (throwCryptoError)
import           Data.ByteString              (ByteString)

import           OIDC.Crypto.Message


testTree = testGroup "Tests.OIDC.Crypto.Message"
    [ testMessageRoundTrip
    ]


testMessageRoundTrip = testProperty "encryptMessage roundtrip" prop
  where
    prop bs = monadicIO $ do
      e <- liftIO $ encryptMessage key nonce (bs :: Int)
      pure $ decryptMessage key e == Just bs

nonce = throwCryptoError $ nonce12 ("0123456789ab" :: ByteString)

key = SymKey "0123456789abcdef0123456789abcdef"

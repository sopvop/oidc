{-# LANGUAGE OverloadedStrings #-}
module OIDC.Web.Mail
  ( SendMail(..)
  , newTestingSendMail
  ) where

import qualified Data.ByteString.Lazy as BSL
import           Data.Semigroup ((<>))
import qualified Data.Text.Lazy as LazyText
import qualified Data.Text.Lazy.Encoding as LazyText
import           System.IO (stdout)

import qualified OIDC.Types.Email as Email

newtype SendMail = SendMail {
  seSendMail :: Email.EmailAddress -> LazyText.Text -> IO ()
}

--newtype NewRegKey = NewRegKey Text



newTestingSendMail :: SendMail
newTestingSendMail = SendMail printIt
  where
    printIt e t = BSL.hPut stdout . LazyText.encodeUtf8
       $ LazyText.fromStrict (Email.toText e)
       <> "\n" <> t

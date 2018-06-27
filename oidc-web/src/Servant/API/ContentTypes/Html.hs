{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
module Servant.API.ContentTypes.Html
  ( Html(..)
  ) where


import qualified Data.ByteString.Lazy as LBS
import           Network.HTTP.Media ((//))
import           Servant.API.ContentTypes

newtype Html = Html LBS.ByteString

instance Accept Html where
  contentType _ = "text" // "html"

instance MimeRender Html Html where
  mimeRender _ (Html bs) = bs
  {-# INLINE mimeRender #-}

{-# LANGUAGE DataKinds     #-}
{-# LANGUAGE TypeOperators #-}
module OIDC.Web
  ( application
  ) where

import           Control.Lens ((^.))
import           Control.Monad.Except (ExceptT (..))
import           Data.Proxy (Proxy (..))

import           Servant.API ((:<|>) (..), (:>), Raw)
import           Servant.Server
    (Application, Handler (..), hoistServerWithContext, serve)
import           Servant.Utils.StaticFiles (serveDirectoryWebApp)

import           OIDC.Web.Handlers (handlers)
import           OIDC.Web.Monad (HasWeb (..), Web, runWebM)
import           OIDC.Web.Routes (Routes)


routes :: Proxy Routes
routes = Proxy

context :: Proxy '[]
context = Proxy

api :: Proxy (Routes :<|> ("static" :> Raw))
api = Proxy

application :: Web -> Application
application env = serve api $
       hoistServerWithContext routes context liftWebM handlers
       :<|> static
  where
    liftWebM act = Handler . ExceptT $
        Right <$> runWebM env act
    static = serveDirectoryWebApp (env^.staticDirectory)

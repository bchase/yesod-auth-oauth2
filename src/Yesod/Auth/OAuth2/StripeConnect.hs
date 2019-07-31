{-# LANGUAGE OverloadedStrings #-}
-- |
--
-- OAuth2 plugin for http://stripe.com
--
-- * Authenticates against stripe
-- * Uses stripe account id as credentials identifier
--
module Yesod.Auth.OAuth2.StripeConnect
    ( oauth2StripeConnect
    , oauth2StripeConnectScoped
    ) where

import Yesod.Auth.OAuth2.Prelude

import qualified Data.Text as T

newtype User = User String

instance FromJSON User where
    parseJSON = withObject "User" $ \o -> User
        <$> o .: "id"

pluginName :: Text
pluginName = "stripe_connect"

defaultScopes :: [Text]
defaultScopes = ["read_write"]

oauth2StripeConnect :: YesodAuth m => Text -> Text -> AuthPlugin m
oauth2StripeConnect = oauth2StripeConnectScoped defaultScopes

oauth2StripeConnectScoped :: YesodAuth m => [Text] -> Text -> Text -> AuthPlugin m
oauth2StripeConnectScoped scopes clientId clientSecret =
    authOAuth2 pluginName oauth2 $ \manager token -> do
        (User userId, userResponse) <- authGetProfile pluginName manager token "https://api.stripe.com/v1/account"

        pure Creds
            { credsPlugin = pluginName
            , credsIdent = T.pack $ show userId
            , credsExtra = setExtra token userResponse
            }
  where
    oauth2 = OAuth2
        { oauthClientId = clientId
        , oauthClientSecret = clientSecret
        , oauthOAuthorizeEndpoint = "https://connect.stripe.com/oauth/authorize"
          `withQuery`
            [ scopeParam "," scopes -- NOTE: actual separator unknown
            ]
        , oauthAccessTokenEndpoint = "https://connect.stripe.com/oauth/token"
          `withQuery`
            [ ("grant_type", "authorization_code")
            ]
        , oauthCallback = Nothing
        }

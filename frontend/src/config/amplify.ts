import { Amplify } from 'aws-amplify'

const cognitoDomain = (import.meta.env.VITE_COGNITO_DOMAIN || '').replace(/^https?:\/\//, '')

const amplifyConfig = {
  Auth: {
    Cognito: {
      userPoolId: import.meta.env.VITE_COGNITO_USER_POOL_ID || '',
      userPoolClientId: import.meta.env.VITE_COGNITO_CLIENT_ID || '',
      signUpVerificationMethod: 'code' as const,
      loginWith: {
        email: true,
        // OAuth2 PKCE for AgentCore direct auth (v6.0)
        ...(cognitoDomain ? {
          oauth: {
            domain: cognitoDomain,
            scopes: ['openid', 'profile'],
            redirectSignIn: [window.location.origin + '/callback'],
            redirectSignOut: [window.location.origin],
            responseType: 'code' as const,
          }
        } : {}),
      },
    },
  },
}

export function configureAmplify() {
  if (amplifyConfig.Auth.Cognito.userPoolId && amplifyConfig.Auth.Cognito.userPoolClientId) {
    Amplify.configure(amplifyConfig)
    return true
  }
  console.warn('Cognito configuration missing. Auth features will be disabled.')
  return false
}

export default amplifyConfig

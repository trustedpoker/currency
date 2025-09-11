import { memo } from 'react';

import { AuthProvider } from '../../types';
import { SWIB_WALLET_MAPPING } from '../provide-btc-logins/provide-btc-logins.component';

export const LoginProviderLabel = memo<{ provider: AuthProvider }>(({ provider }) => {
  switch (provider.type) {
    case "line":
      return <>Line</>;
    case "google":
      return <>Google</>;
    case "apple":
      return <>Apple</>;
    case "facebook":
      return <>Facebook</>;
    case "twitter":
      return <>X</>;
    case "internet_identity":
      return <>Internet Identity</>;
    case "github":
      return <>GitHub</>;
    case "email_passwordless":
      return <>Email</>;
    case 'siwb':
      return <>{SWIB_WALLET_MAPPING[provider.provider].label}</>
  }
});

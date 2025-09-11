import { Image, ListItem } from '@zk-game-dao/ui';
import { memo, useMemo } from 'react';

import AppleIcon from '../../../icons/login-providers/apple.svg';
import Facebook from '../../../icons/login-providers/facebook.svg';
import GitHub from '../../../icons/login-providers/github.svg';
import GoogleIcon from '../../../icons/login-providers/google.svg';
import InternetIdentity from '../../../icons/login-providers/internet_identity.svg';
import Line from '../../../icons/login-providers/line.svg';
import Twitter from '../../../icons/login-providers/twitter.svg';
import { SocialLoginProviderKey, SocialLoginProviders } from '../../types';
import { LoginProviderLabel } from './login-provider-label.component';

const LoginProviderListIcon: Record<SocialLoginProviderKey, string> = {
  google: GoogleIcon,
  apple: AppleIcon,
  facebook: Facebook,
  twitter: Twitter,
  internet_identity: InternetIdentity,
  github: GitHub,
  line: Line,
};

export const LoginProviderListItemComponent = memo<{
  loginProvider: SocialLoginProviderKey;
  login(): Promise<void>;
}>(({ loginProvider, login }) => {

  const type = useMemo((): 'social' | 'wallet' => SocialLoginProviders.includes(loginProvider as SocialLoginProviderKey) ? 'social' : 'wallet', [loginProvider]);

  return (
    <ListItem
      onClick={login}
      icon={
        <div className="w-6 ml-5 mr-4">
          <Image
            src={LoginProviderListIcon[loginProvider]}
            type="svg"
            alt={`${loginProvider} logo`}
          />
        </div>
      }
    >
      <div className="inline">
        <p className="hidden lg:inline-flex">{type === 'social' ? 'Continue with ' : 'Connect to '}</p> <LoginProviderLabel provider={{ type: loginProvider }} />
      </div>
    </ListItem>
  )
});

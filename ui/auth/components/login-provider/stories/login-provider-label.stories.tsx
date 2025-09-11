import type { Meta, StoryObj } from '@storybook/react';

import { SocialLoginProviderKey, SocialLoginProviders } from '../../../types/web3auth';
import {
  SUPPORTED_WALLETS, SupportedSIWBProvider
} from '../../provide-btc-logins/provide-btc-logins.component';
import {
  LoginProviderLabel as LoginProviderLabelComponent
} from '../login-provider-label.component';

type Props = {
  type: SocialLoginProviderKey | 'email_passwordless' | SupportedSIWBProvider;
}

const meta: Meta<Props> = {
  title: 'Login/LoginProvider/Label',
  argTypes: {
    type: {
      control: {
        type: 'select',
      },
      options: [SocialLoginProviders, 'email_passwordless'],
    },
  },
  component: ({ type }) => {
    if (SUPPORTED_WALLETS.indexOf(type) !== -1)
      return <LoginProviderLabelComponent provider={{ type: 'siwb', provider: type as SupportedSIWBProvider }} />;
    return <LoginProviderLabelComponent provider={{ type }} />;
  },
};

export default meta;
type Story = StoryObj<Props>;

export const Email: Story = { args: { type: 'email_passwordless' } };
export const Google: Story = { args: { type: 'google' } };
export const Apple: Story = { args: { type: 'apple' } };
export const Facebook: Story = { args: { type: 'facebook' } };
export const Twitter: Story = { args: { type: 'twitter' } };
export const InternetIdentity: Story = { args: { type: 'internet_identity' } };
export const GitHub: Story = { args: { type: 'github' } };
export const Line: Story = { args: { type: 'line' } };
export const SIWBUnisat: Story = { args: { type: 'unisat' } };
export const SIWBXverse: Story = { args: { type: 'xverse' } };
// export const SIWBPhantom: Story = { args: { type: 'phantom' } };
export const SIWBOKX: Story = { args: { type: 'okx' } };
export const SIWBWizz: Story = { args: { type: 'wizz' } };
export const SIWBLeather: Story = { args: { type: 'leather' } };


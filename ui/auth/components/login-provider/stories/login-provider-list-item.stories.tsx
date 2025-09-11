import { SocialLoginProviders } from '../../../types/web3auth';
import { LoginProviderListItemComponent } from '../login-provider-list-item.component';

import type { Meta, StoryObj } from '@storybook/react';

const meta: Meta<typeof LoginProviderListItemComponent> = {
  title: 'Login/LoginProvider/ListItem',
  argTypes: {
    loginProvider: {
      control: {
        type: 'select',
      },
      options: SocialLoginProviders,
    },
  },
  args: {
    login: () => Promise.resolve(),
  },
  component: LoginProviderListItemComponent
};

export default meta;
type Story = StoryObj<typeof LoginProviderListItemComponent>;

export const Google: Story = { args: { loginProvider: 'google' } };
export const Apple: Story = { args: { loginProvider: 'apple' } };
export const Facebook: Story = { args: { loginProvider: 'facebook' } };
export const Twitter: Story = { args: { loginProvider: 'twitter' } };
export const InternetIdentity: Story = { args: { loginProvider: 'internet_identity' } };
export const GitHub: Story = { args: { loginProvider: 'github' } };
export const Line: Story = { args: { loginProvider: 'line' } };
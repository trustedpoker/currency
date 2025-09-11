import { BTCWalletComponent } from '../btc-wallet.component';
import {
  WalletStoryProviderArgTypes, WalletStoryProviderProps, WalletStoryProviderRenderFactory
} from '../../wallet-modal-content/stories/wallet-story-provider';

import type { Meta, StoryObj } from '@storybook/react';

const meta: Meta<WalletStoryProviderProps> = {
  title: 'BTC Wallet',
  ...WalletStoryProviderArgTypes,
  render: WalletStoryProviderRenderFactory(() => <BTCWalletComponent onBack={() => { }} />),
};

export default meta;
type Story = StoryObj<WalletStoryProviderProps>;

export const Modal: Story = {};

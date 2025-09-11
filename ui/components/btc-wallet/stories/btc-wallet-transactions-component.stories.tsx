import { WalletStoryProviderProps } from '../../wallet-modal-content/stories/wallet-story-provider';
import { BTCWalletTransactions } from '../btc-wallet-transactions.component';

import type { Meta, StoryObj } from '@storybook/react';
const meta: Meta<typeof BTCWalletTransactions> = {
  title: 'BTC Wallet/Transactions',
  component: BTCWalletTransactions,
  args: {
    requiredConfirmations: 6,
    btcAddress: 'bc1q0hmdmdl0phr6q6yk7tflmf7xdx4c43mmn250ex',
  }
};

export default meta;
type Story = StoryObj<WalletStoryProviderProps>;

export const Transactions: Story = {};

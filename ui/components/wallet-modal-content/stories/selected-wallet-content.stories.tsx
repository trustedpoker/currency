import { Modal } from '@zk-game-dao/ui';
import { SelectedWalletContent } from '../selected-wallet-content.component';
import {
  WalletStoryProviderArgTypes,
  WalletStoryProviderProps,
  WalletStoryProviderRenderFactory,
} from './wallet-story-provider';

import type { Meta, StoryObj } from '@storybook/react';

const meta: Meta<WalletStoryProviderProps> = {
  title: 'Wallet/SelectedWallet',
  ...WalletStoryProviderArgTypes,
  render: WalletStoryProviderRenderFactory(({ currency }) => <SelectedWalletContent currency={currency} onBack={() => { }} />),
};

export default meta;
type Story = StoryObj<WalletStoryProviderProps>;

export const ICP: Story = { args: { selectedWallet: 'ICP' } };
export const ICPInModal: Story = {
  args: { selectedWallet: 'ICP' },
  decorators: [(Story) => <Modal>{Story()}</Modal>]
};
export const BTC: Story = { args: { selectedWallet: 'BTC' } };
export const ETH: Story = { args: { selectedWallet: 'ETH' } };
export const DCD: Story = { args: { selectedWallet: 'DCD' } };

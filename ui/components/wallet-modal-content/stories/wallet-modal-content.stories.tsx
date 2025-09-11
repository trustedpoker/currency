import { WalletModalContent } from '../wallet-modal-content.component';
import {
  WalletStoryProviderArgTypes,
  WalletStoryProviderProps,
  WalletStoryProviderRenderFactory,
} from './wallet-story-provider';

import type { Meta, StoryObj } from '@storybook/react';

const meta: Meta<WalletStoryProviderProps> = {
  title: 'Wallet/Modal',
  ...WalletStoryProviderArgTypes,
  render: WalletStoryProviderRenderFactory(() => <WalletModalContent onBack={() => { }} />),
};

export default meta;
type Story = StoryObj<WalletStoryProviderProps>;

export const Modal: Story = {};

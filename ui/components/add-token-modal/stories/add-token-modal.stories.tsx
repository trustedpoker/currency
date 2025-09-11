import type { Meta, StoryObj } from '@storybook/react';

import { AddTokenModal } from '../add-token-modal.component';
import { List, ListItem } from '@zk-game-dao/ui';
import { useState } from 'react';

const meta: Meta<typeof AddTokenModal> = {
  title: 'UI/AddTokenModal',
  component: AddTokenModal,
  args: {
    isOpen: true,
    onClose: () => { },
  }
};

export default meta;
type Story = StoryObj<typeof AddTokenModal>;

export const Default: Story = {};
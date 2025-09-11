import type { Meta, StoryObj } from '@storybook/react';

import { SignupModalComponent } from '../signup-modal.component';

const meta: Meta<typeof SignupModalComponent> = {
  title: 'Login/SignupModal',
  component: SignupModalComponent,
  args: {
    onClose: () => {},
  }
};

export default meta;
type Story = StoryObj<typeof SignupModalComponent>;

export const SignupModal: Story = {};
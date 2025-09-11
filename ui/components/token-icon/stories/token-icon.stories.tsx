import type { Meta, StoryObj } from '@storybook/react';

import { DCD_MOCK, NFID_MOCK, YUKU_MOCK } from '../../../../.storybook/__mocks__/tokens';
import { CurrencyMetaIconComponent } from '../token-icon.component';

const meta: Meta<typeof CurrencyMetaIconComponent> = {
  title: 'UI/Icons/MetaToken',
  component: CurrencyMetaIconComponent,
  args: {
    className: 'size-5',
  }
};

export default meta;
type Story = StoryObj<typeof CurrencyMetaIconComponent>;

export const DCD: Story = {
  args: {
    meta: DCD_MOCK.meta
  }
};

export const NFID: Story = {
  args: {
    meta: NFID_MOCK.meta
  }
};

export const YUKU: Story = {
  args: {
    meta: YUKU_MOCK.meta
  }
};

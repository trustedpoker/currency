import type { Meta, StoryObj } from '@storybook/react';

import { useState } from 'react';

import { List, ListItem } from '@zk-game-dao/ui';

import { DCD_MOCK } from '../../../../.storybook/__mocks__/tokens';
import { CurrencyInputComponent } from '../currency-input.component';

const meta: Meta<typeof CurrencyInputComponent> = {
  title: 'UI/Inputs/Currency',

  render: (args) => {
    const [value, setValue] = useState(args.value);
    return <CurrencyInputComponent {...args} value={value} onChange={setValue} />;
  },
  args: {
    onChange: (value) => console.log('onChange', value),
    currencyType: { Real: { BTC: null } },
    value: 1110n,
    min: 0n,
    max: 1000000000n,
  }
};

export default meta;
type Story = StoryObj<typeof CurrencyInputComponent>;

export const Default: Story = {};
export const DefaultICP: Story = { args: { currencyType: { Real: { ICP: null } }, value: 100000n } };
export const DefaultDCD: Story = { args: { currencyType: DCD_MOCK.currencyType, value: 100000n } };
export const SmallAmount: Story = {
  args: {
    value: 1n,
  }
};
export const InList: Story = {
  decorators: [
    (Story) => (
      <List>
        <ListItem>Before</ListItem>
        {Story()}
        <ListItem>After</ListItem>
      </List>
    ),
  ],
  args: {
    value: 1n,
    currencyType: { Fake: null },
  }
};

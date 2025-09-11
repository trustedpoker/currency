import type { Meta, StoryObj } from '@storybook/react';

import { RealCurrencyInputComponent } from '../currency-type-input.component';
import { List, ListItem } from '@zk-game-dao/ui';
import { useState } from 'react';

const meta: Meta<typeof RealCurrencyInputComponent> = {
  title: 'UI/Inputs/RealCurrencyType',
  render: (args) => {
    const [selectedValue, setSelectedValue] = useState(args.value);
    return <RealCurrencyInputComponent {...args} value={selectedValue} onChange={setSelectedValue} />;
  },
  args: {
    label: 'Hello world',
  }
};

export default meta;
type Story = StoryObj<typeof RealCurrencyInputComponent>;

export const Default: Story = {};
export const NoLabel: Story = { args: { label: undefined } };
export const WithSelection: Story = { args: { value: { ICP: null } } };
export const InList: Story = {
  decorators: [
    (Story) => (
      <List>
        <ListItem>ASDF</ListItem>
        <Story />
        <ListItem>BSDF</ListItem>
      </List>
    ),
  ],
}
export const InListWithSelection: Story = {
  args: { value: { ICP: null } },
  decorators: [
    (Story) => (
      <List>
        <ListItem>ASDF</ListItem>
        <Story />
        <ListItem>BSDF</ListItem>
      </List>
    ),
  ],
}

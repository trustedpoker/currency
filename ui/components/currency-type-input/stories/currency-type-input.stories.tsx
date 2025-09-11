import type { Meta, StoryObj } from '@storybook/react';

import { CurrencyTypeInputComponent } from '../currency-type-input.component';
import { List, ListItem } from '@zk-game-dao/ui';

const meta: Meta<typeof CurrencyTypeInputComponent> = {
  title: 'UI/Inputs/CurrencyType',
  component: CurrencyTypeInputComponent,
  args: {
    label: 'Hello world',
    onChange: (value) => console.log('onChange', value),
  }
};

export default meta;
type Story = StoryObj<typeof CurrencyTypeInputComponent>;

export const Default: Story = {};
export const NoLabel: Story = { args: { label: undefined } };
export const WithSelection: Story = { args: { value: { Fake: null } } };
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
  args: { value: { Fake: null } },
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

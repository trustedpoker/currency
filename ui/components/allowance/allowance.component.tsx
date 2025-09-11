import { addMinutes } from 'date-fns';
import { memo } from 'react';

import { List, ListItem, useIsInList } from '@zk-game-dao/ui';

import { useAllowance } from '../../hooks/allowance';
import { AllowanceAddressData } from '../../types/allowance.context';
import { CurrencyComponent } from '../currency/currency.component';

export const AllowanceComponent = memo<AllowanceAddressData>(({ currencyType, receiver, name }) => {

  const allowance = useAllowance({ currencyType: currencyType, receiver, name });

  const isInList = useIsInList();

  if (!isInList)
    return (
      <List label={<>Allownce for {name}</>}>
        <ListItem
          rightLabel={<CurrencyComponent currencyValue={allowance.allowance} currencyType={currencyType} />}
          onClick={() => allowance.update({ amount: 0n, reason: "Revoke" }, addMinutes(new Date(), 2))}
        >
          Amount
        </ListItem>
        <ListItem>Principal</ListItem>
      </List>
    );

  return (
    <ListItem
      rightLabel={<CurrencyComponent currencyValue={allowance.allowance} currencyType={currencyType} />}
      onClick={() => allowance.update({ amount: 0n, reason: "Revoke" }, addMinutes(new Date(), 2))}
    >
      Allowance of {name}
    </ListItem>
  );
});
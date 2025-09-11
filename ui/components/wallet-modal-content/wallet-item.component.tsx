import { memo } from 'react';

import { ListItem } from '@zk-game-dao/ui';

import { useBalance } from '../../hooks/balance';
import { useCurrencyManagerMeta } from '../../hooks/currency-manager.hook';
import { Currency } from '../../types/currency';
import { CurrencySerializer } from '../../utils/serialize';
import { TokenAmountToString } from '../../utils/token-amount-conversion';
import {
  CurrencyTypeLabelComponent, CurrencyTypeSymbolComponent
} from '../currency-type/currency-type.component';
import { CurrencyIconComponent } from '../token-icon/token-icon.component';

export const WalletItem = memo<{ currency: Currency; onClick(): void; }>(({ currency, onClick }) => {
  const balance = useBalance({ Real: currency });
  const meta = useCurrencyManagerMeta({ Real: currency });

  return (
    <ListItem
      icon={<div className='size-12 flex justify-center items-center p-2'><CurrencyIconComponent className='' currency={currency} /></div>}
      rightLabel={TokenAmountToString(balance, meta)}
      onClick={onClick}
    >
      <div className='flex flex-col'>
        <div className='type-title'>
          <CurrencyTypeLabelComponent currencyType={{ Real: currency }} />
        </div>
        <div className='type-caption text-material-medium-2'>
          <CurrencyTypeSymbolComponent currencyType={{ Real: currency }} />
        </div>
      </div>
    </ListItem>
  );
}, (prev, next) => CurrencySerializer.serialize(prev.currency) === CurrencySerializer.serialize(next.currency) && prev.onClick === next.onClick);

import { DropdownInputComponent } from '@zk-game-dao/ui';
import { memo, ReactNode } from 'react';

import { useManualWallet } from '../../types/manual-wallet-context';
import { WalletType, WalletTypeLabel, WalletTypes } from '../wallet-type-label/wallet-type-label.component';

export const ManualWalletSelectorComponent = memo<{ label?: ReactNode }>(
  ({ label = "Wallet" }) => {
    const { walletType, setWalletType } = useManualWallet();

    return (
      <DropdownInputComponent
        label={label}
        value={walletType}
        onChange={(v) => setWalletType(v as WalletType)}
        options={WalletTypes.map((t) => ({
          value: t,
          label: <WalletTypeLabel walletType={t} />,
        }))}
      />
    );
  },
);

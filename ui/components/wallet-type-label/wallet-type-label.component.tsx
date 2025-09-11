import { memo } from "react";
import { EIP6963ProviderInfo } from "../../types/EIP6963.context";

import PlugIcon from "../../icons/wallets/plug-logo.svg";
import BitfinityWalletIcon from "../../icons/wallets/bitfinity-wallet-logo.svg";
import MetamaskIcon from "../../icons/wallets/metamask.svg";

export const WalletTypes = [
  // "stoic",
  "plug",
  "bitfinityWallet",
  // "phantom",
] as const;
export type WalletType = (typeof WalletTypes)[number];

export const ETHExternalWalletTypes = [
  'metamask',
];
export type ETHExternalWalletType = (typeof ETHExternalWalletTypes)[number];

export const WalletTypeLabel = memo<{ walletType?: WalletType | ETHExternalWalletType; eip6963?: EIP6963ProviderInfo }>(
  ({ walletType, eip6963 }) => {
    switch (walletType || eip6963?.name) {
      case "plug":
        return (
          <div className="flex flex-row justify-center items-center">
            <img src={PlugIcon} className="w-5 h-5 mr-1 inline" />
            <span className="mr-1">Plug</span>
          </div>
        );
      case "bitfinityWallet":
        return (
          <div className="flex flex-row justify-center items-center">
            <img
              src={BitfinityWalletIcon}
              className="w-5 h-5 mr-1 inline"
            />
            <span>Bitfinity</span>
          </div>
        );
      // case "phantom":
      //   return (
      //     <div className="flex flex-row justify-center items-center">
      //       <img
      //         src="/icons/Phantom-Icon-Purple.svg"
      //         className="w-5 h-5 mr-2 inline"
      //       />
      //       <span>Phantom</span>
      //     </div>
      //   );
      case 'MetaMask':
        return (
          <div className="flex flex-row justify-center items-center">
            <img
              src={MetamaskIcon}
              className="w-5 h-5 mr-2 inline"
            />
            <span>Metamask</span>
          </div>
        );
      default:
        if (eip6963)
          return (
            <div className="flex flex-row justify-center items-center">
              <img
                src={eip6963.icon}
                className="w-5 h-5 mr-2 inline"
              />
              <span>{eip6963.name}</span>
            </div>
          );
        return <span>{walletType}</span>;
    }
  },
);

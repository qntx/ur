import { QRCodeSVG } from "qrcode.react";
import type { JSX } from "react";

import { toQrString } from "@qntx/ur";

export function Qr({ value, label }: { value: string; label?: string }): JSX.Element {
  return (
    <figure className="qr">
      <QRCodeSVG value={toQrString(value)} size={168} marginSize={2} title={label ?? "UR QR"} />
      {label === undefined ? null : <figcaption>{label}</figcaption>}
    </figure>
  );
}

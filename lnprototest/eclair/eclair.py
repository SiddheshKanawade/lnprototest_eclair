import io
import pyln.client
import pyln.proto.wire
import lnprototest
import coincurve
import socket

from typing import Any, List, Optional
from lnprototest import (
    Event,
    ExpectMsg,
    EventError,
    SpecFileError,
    KeySet,
    Conn,
    namespace,
    MustNotMsg,
)
from contextlib import closing

from pyln.proto.message import (
    Message,
    FieldType,
    DynamicArrayType,
    EllipsisArrayType,
    SizedArrayType,
)

class EclairConn(lnprototest.Conn):
    def __init__(self, connprivkey: str, port: int):
        super().__init__(connprivkey)
        self.connection = pyln.proto.wire.connect(
            coincurve.PrivateKey.from_hex(connprivkey),
            pyln.proto.wire.PublicKey.from_hex(
                "035d09b72ca1fbbee12591f3cb5335348055135c7a1cec07f91c549093a3878181"),
            "127.0.0.1",
            port,
        )

class Runner(lnprototest.Runner):
    def __init__(self, config: Any):
        super().__init__(config)
        self.running = False
        self.rpc = None
        self.bitcoind = None
        self.proc = None
        self.lightning_port  =self.__reserve()
        # self.bitcoin = pyln.client.Lightning("lightning-rpc")
    
    # Make copy of dummy runner and then try updating it to work with eclair
    def __reserve(self) -> int:
        """
        When python asks for a free port from the os, it is possible that
        with concurrent access, the port that is picked is a port that is not free
        anymore when we go to bind the daemon like bitcoind port.

        Source: https://stackoverflow.com/questions/1365265/on-localhost-how-do-i-pick-a-free-port-number
        """
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(("", 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]
    
    def get_keyset(self) -> KeySet:
        return KeySet(
            revocation_base_secret="11",
            payment_base_secret="12",
            htlc_base_secret="14",
            delayed_payment_base_secret="13",
            shachain_seed="FF" * 32,
        )

    def add_startup_flag(self, flag: str) -> None:
        if self.config.getoption("verbose"):
            print("[ADD STARTUP FLAG {}]".format(flag))
        return

    def get_node_privkey(self) -> str:
        return "01"

    def get_node_bitcoinkey(self) -> str:
        return "10"

    def has_option(self, optname: str) -> Optional[str]:
        return None

    def start(self) -> None:
        self.blockheight = 102

    def stop(self) -> None:
        pass

    def restart(self) -> None:
        super().restart()
        if self.config.getoption("verbose"):
            print("[RESTART]")
        self.blockheight = 102

    def connect(self, _: Event, connprivkey: str) -> None:
        self.add_conn(EclairConn(connprivkey, self.lightning_port))

    def getblockheight(self) -> int:
        return self.blockheight

    def trim_blocks(self, newheight: int) -> None:
        if self.config.getoption("verbose"):
            print("[TRIMBLOCK TO HEIGHT {}]".format(newheight))
        self.blockheight = newheight

    def add_blocks(self, event: Event, txs: List[str], n: int) -> None:
        if self.config.getoption("verbose"):
            print("[ADDBLOCKS {} WITH {} TXS]".format(n, len(txs)))
        self.blockheight += n

    def disconnect(self, event: Event, conn: Conn) -> None:
        super().disconnect(event, conn)
        if self.config.getoption("verbose"):
            print("[DISCONNECT {}]".format(conn))

    def recv(self, event: Event, conn: Conn, outbuf: bytes) -> None:
        if self.config.getoption("verbose"):
            print("[RECV {} {}]".format(event, outbuf.hex()))

    def fundchannel(
        self,
        event: Event,
        conn: Conn,
        amount: int,
        feerate: int = 253,
        expect_fail: bool = False,
    ) -> None:
        if self.config.getoption("verbose"):
            print(
                "[FUNDCHANNEL TO {} for {} at feerate {}. Expect fail? {}]".format(
                    conn, amount, feerate, expect_fail
                )
            )

    def init_rbf(
        self,
        event: Event,
        conn: Conn,
        channel_id: str,
        amount: int,
        utxo_txid: str,
        utxo_outnum: int,
        feerate: int,
    ) -> None:
        if self.config.getoption("verbose"):
            print(
                "[INIT_RBF TO {} (channel {}) for {} at feerate {}. {}:{}".format(
                    conn, channel_id, amount, feerate, utxo_txid, utxo_outnum
                )
            )

    def invoice(self, event: Event, amount: int, preimage: str) -> None:
        if self.config.getoption("verbose"):
            print("[INVOICE for {} with PREIMAGE {}]".format(amount, preimage))

    def accept_add_fund(self, event: Event) -> None:
        if self.config.getoption("verbose"):
            print("[ACCEPT_ADD_FUND]")

    def addhtlc(self, event: Event, conn: Conn, amount: int, preimage: str) -> None:
        if self.config.getoption("verbose"):
            print(
                "[ADDHTLC TO {} for {} with PREIMAGE {}]".format(conn, amount, preimage)
            )

    @staticmethod
    def fake_field(ftype: FieldType) -> str:
        if isinstance(ftype, DynamicArrayType) or isinstance(ftype, EllipsisArrayType):
            # Byte arrays are literal hex strings
            if ftype.elemtype.name == "byte":
                return ""
            return "[]"
        elif isinstance(ftype, SizedArrayType):
            # Byte arrays are literal hex strings
            if ftype.elemtype.name == "byte":
                return "00" * ftype.arraysize
            return (
                "["
                + ",".join([Runner.fake_field(ftype.elemtype)] * ftype.arraysize)
                + "]"
            )
        elif ftype.name in (
            "byte",
            "u8",
            "u16",
            "u32",
            "u64",
            "tu16",
            "tu32",
            "tu64",
            "bigsize",
            "varint",
        ):
            return "0"
        elif ftype.name in ("chain_hash", "channel_id", "sha256"):
            return "00" * 32
        elif ftype.name == "point":
            return "038f1573b4238a986470d250ce87c7a91257b6ba3baf2a0b14380c4e1e532c209d"
        elif ftype.name == "short_channel_id":
            return "0x0x0"
        elif ftype.name == "signature":
            return "01" * 64
        else:
            raise NotImplementedError(
                "don't know how to fake {} type!".format(ftype.name)
            )

    def get_output_message(self, conn: Conn, event: ExpectMsg) -> Optional[bytes]:
        if self.config.getoption("verbose"):
            print("[GET_OUTPUT_MESSAGE {}]".format(conn))

        # We make the message they were expecting.
        msg = Message(event.msgtype, **event.resolve_args(self, event.kwargs))

        # Fake up the other fields.
        for m in msg.missing_fields():
            ftype = msg.messagetype.find_field(m.name)
            msg.set_field(m.name, self.fake_field(ftype.fieldtype))

        binmsg = io.BytesIO()
        msg.write(binmsg)
        return binmsg.getvalue()

    def expect_tx(self, event: Event, txid: str) -> None:
        if self.config.getoption("verbose"):
            print("[EXPECT-TX {}]".format(txid))

    def check_error(self, event: Event, conn: Conn) -> Optional[str]:
        super().check_error(event, conn)
        if self.config.getoption("verbose"):
            print("[CHECK-ERROR {}]".format(event))
        return "Dummy error"

    def check_final_error(
        self,
        event: Event,
        conn: Conn,
        expected: bool,
        must_not_events: List[MustNotMsg],
    ) -> None:
        pass

    def close_channel(self, channel_id: str) -> bool:
        if self.config.getoption("verbose"):
            print("[CLOSE-CHANNEL {}]".format(channel_id))
        return True

    def is_running(self) -> bool:
        return True

    def teardown(self):
        pass

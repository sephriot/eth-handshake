use std::{net::{IpAddr, SocketAddr}, io};

use alloy_rlp::{BytesMut, BufMut};
use tokio::{net::TcpStream, io::AsyncWriteExt};



pub struct TcpStreamHandler {
    pub stream: TcpStream,
}

impl TcpStreamHandler {
    pub async fn new(ip_addr: IpAddr, port: u16) -> Self {
        let addr: SocketAddr = SocketAddr::new(ip_addr, port);
        let stream = TcpStream::connect(addr).await.unwrap();
        Self {
            stream
        }
    }

    pub async fn write(&mut self, data: &BytesMut) -> Result<(), std::io::Error> {
        self.stream.write(data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn read(&mut self) -> Result<BytesMut, std::io::Error> {
        let mut data = BytesMut::new();
        loop {
            // Wait for the socket to be readable
            println!("Waiting for stream to be readable");
            self.stream.readable().await?;
            // if let Err(_) = tokio::time::timeout(Duration::from_millis(self.read_ready_timeout_ms), self.stream.readable()).await{
            //     println!("did not receive value within {:?} ms, returning", self.read_ready_timeout_ms);
            //     break;
            // }
            println!("Stream readable");
            // Try to read data, this may still fail with `WouldBlock`
            // if the readiness event is a false positive.
            println!("Try reading");

            // Creating the buffer **after** the `await` prevents it from
            // being stored in the async task.
            let mut buf = [0; 4096];
            match self.stream.try_read(&mut buf) {
                Ok(0) => {
                    println!("Read 0, break");
                    break
                }
                Ok(n) => {
                    println!("read {} bytes", n);
                    data.put_slice(&buf[0..n]);
                    break;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    println!("Would block");
                    continue;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
        return Ok(data)
    }
}
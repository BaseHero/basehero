use std::{net::TcpListener, sync::mpsc, thread, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use url::Url;

pub struct DelayProxy {
    url: Url,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

async fn forward(
    mut src: impl AsyncRead + Unpin,
    mut dst: impl AsyncWrite + Unpin,
    delay: Duration,
) {
    let mut buf = [0u8; 16384];
    while let Ok(n) = src.read(&mut buf).await {
        if n == 0 {
            break;
        }
        tokio::time::sleep(delay).await;
        if dst.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = dst.shutdown().await;
}

impl DelayProxy {
    pub fn start(target: Url, rtt: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("proxy port");
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let (ready, receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                ready.send(()).unwrap();
                loop {
                    tokio::select! {
                        _ = &mut stopped => break,
                        result = listener.accept() => {
                            let Ok((incoming, _)) = result else { break };
                            let target = target.clone();
                            tokio::spawn(async move {
                                let Ok(outgoing) = TcpStream::connect((target.host_str().unwrap(), target.port_or_known_default().unwrap())).await else { return };
                                let (read_in, write_in) = incoming.into_split();
                                let (read_out, write_out) = outgoing.into_split();
                                tokio::join!(forward(read_in, write_out, rtt / 2), forward(read_out, write_in, rtt / 2));
                            });
                        }
                    }
                }
            });
        });
        receiver.recv().expect("proxy ready");
        Self {
            url,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    pub fn url(&self) -> Url {
        self.url.clone()
    }
}

impl Drop for DelayProxy {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

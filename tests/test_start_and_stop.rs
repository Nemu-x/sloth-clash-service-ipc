#![cfg(feature = "standalone")]
#[cfg(test)]
mod tests {
    use anyhow::Result;
    use kode_bridge::IpcHttpClient;
    use serial_test::serial;
    use sloth_clash_service_ipc::{IPC_PATH, IpcCommand, run_ipc_server, stop_ipc_server};
    use tracing::debug;

    async fn connect_ipc() -> Result<IpcHttpClient> {
        debug!("Connecting to IPC at {}", IPC_PATH);
        let client = kode_bridge::IpcHttpClient::new(IPC_PATH)?;
        client.get(IpcCommand::Magic.as_ref()).send().await?;
        Ok(client)
    }

    #[tokio::test]
    #[serial]
    async fn test_stop_ipc_server_when_not_running() {
        assert!(
            stop_ipc_server().await.is_ok(),
            "Stopping IPC server when not running should return Ok"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_connect_ipc_when_server_not_running() {
        let _ = stop_ipc_server().await;
        assert!(
            connect_ipc().await.is_err(),
            "Connecting to IPC when server is not running should return an error"
        );
    }

    async fn start_and_stop_ipc_server_helper() {
        let _ = stop_ipc_server().await;

        let server_handle = tokio::spawn(async {
            assert!(
                run_ipc_server().await.is_ok(),
                "Starting IPC server should return Ok"
            );
        });

        let client = {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            connect_ipc().await
        };

        assert!(
            client.is_ok(),
            "Should be able to connect to IPC server after starting"
        );

        assert!(
            stop_ipc_server().await.is_ok(),
            "Stopping IPC server after starting should return Ok"
        );

        let _ = server_handle.await;

        assert!(
            connect_ipc().await.is_err(),
            "Should not be able to connect after stopping IPC server"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_start_and_stop_ipc_server() {
        start_and_stop_ipc_server_helper().await;
        #[cfg(windows)]
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }

    // The RemoveTun endpoint is a recovery hook: it must route, authenticate and
    // answer 200, reporting how many adapters it removed — exactly what the app
    // relies on to decide whether to retry the TUN create.
    //
    // On Windows the handler runs a REAL PnP sweep that removes every wintun
    // adapter, which would drop a live VPN if the box happens to be connected
    // while `cargo test` runs. So the destructive call is opt-in there via
    // SLOTH_TEST_REMOVE_TUN=1; without it we only assert the route exists (a bad
    // path would 404, not time out). On non-Windows the handler is a no-op, so
    // the full contract is always exercised in CI.
    #[tokio::test]
    #[serial]
    async fn test_remove_tun_endpoint_is_reachable() {
        use sloth_clash_service_ipc::{connect, remove_tun};

        #[cfg(windows)]
        let destructive_ok = std::env::var("SLOTH_TEST_REMOVE_TUN").as_deref() == Ok("1");
        #[cfg(not(windows))]
        let destructive_ok = true;

        if !destructive_ok {
            println!("skipping the live RemoveTun sweep (set SLOTH_TEST_REMOVE_TUN=1 to run it)");
            return;
        }

        let _ = stop_ipc_server().await;
        let server_handle = tokio::spawn(async {
            let _ = run_ipc_server().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(connect().await.is_ok(), "should connect before RemoveTun");

        let resp = remove_tun().await;
        assert!(
            resp.is_ok(),
            "RemoveTun should answer, got {:?}",
            resp.err()
        );
        let resp = resp.unwrap();
        assert_eq!(resp.code, 0, "RemoveTun should report success");
        assert!(
            resp.data.is_some(),
            "RemoveTun should report a removed-adapter count"
        );

        let _ = stop_ipc_server().await;
        let _ = server_handle.await;
        #[cfg(windows)]
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_start_and_stop_ipc_server_multiple_times() {
        for i in 0..50 {
            println!("Iteration {}", i);

            let handle = run_ipc_server().await.unwrap();

            assert!(connect_ipc().await.is_ok(), "Should connect after starting");

            stop_ipc_server().await.unwrap();

            // 等待 server 完全退出
            let res = handle.await.unwrap();
            assert!(res.is_ok(), "server should exit cleanly");
        }
    }
}

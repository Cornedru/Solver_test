use cf::solver::TurnstileSolver;
use std::sync::Arc;
use std::time::Instant;

#[tokio::main]
async fn main() {
    let solver = Arc::new(
        TurnstileSolver::new().await.unwrap()
    );

    let t = Instant::now();

    let mut task = solver
        .create_task(
            "0x4AAAAAABs37s-ih7Jepz0J",
            "https://mune.rs/",
            None,
            None,
        )
        .await
        .unwrap();

    let result = task.solve().await;

    match result {
        Ok(token) => println!("{:?}", token),
        Err(e) => println!("err: {}", e.root_cause()),
    }

    println!("Took {:?}", t.elapsed());
}

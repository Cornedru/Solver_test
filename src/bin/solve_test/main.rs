// use cf::solver::TurnstileSolver;
// use std::sync::Arc;
// use std::time::Instant;

// #[tokio::main]
// async fn main() {
//     let solver = Arc::new(TurnstileSolver::new().await);

//     let t = Instant::now();
//     let mut task = solver
//         .create_task(
//             "0x4AAAAAABdbdHypG5Crbw0P",
//             "https://mune.sh/",
//             None,
//             None,
//         )
//         .await.unwrap();

//     let result = task.solve().await;

//     if let Ok(result) = result {
//         println!("{:?}", result);
//     } else {
//         println!("err: {}", result.as_ref().unwrap_err().root_cause());
//     }
    
//     println!("Took {:?}", t.elapsed());
// }

use cf::solver::TurnstileSolver;
use std::sync::Arc;
use std::time::Instant;

#[tokio::main]
async fn main() {
    // Initialisation du solver (charge les configs et le fingerprint)
    let solver = Arc::new(TurnstileSolver::new().await);

    println!("🚀 Démarrage du test avec la clé DUMMY Cloudflare...");
    let t = Instant::now();

    // UTILISATION DES CLÉS DE TEST OFFICIELLES CLOUDFLARE
    // SiteKey: 1x00000000000000000000AA (Force le succès)
    // URL: https://cloudflare.com (Domaine arbitraire accepté par la clé de test)
    let task_result = solver
        .create_task(
            "1x00000000000000000000AA",
            "https://cloudflare.com",
            None,
            None,
        )
        .await;

    match task_result {
        Ok(mut task) => {
            println!("✅ Tâche créée avec succès. Résolution en cours...");
            match task.solve().await {
                Ok(result) => {
                    println!("\n🎉 SUCCÈS ! Token obtenu :");
                    println!("Token: {}", result.token);
                    println!("Interactive: {}", result.interactive);
                },
                Err(e) => println!("\n❌ ÉCHEC de la résolution : {}", e),
            }
        },
        Err(e) => println!("\n❌ ÉCHEC de la création de tâche : {}", e),
    }
    
    println!("⏱️ Temps écoulé : {:?}", t.elapsed());
}

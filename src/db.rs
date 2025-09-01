use sqlx::PgPool;
use tokio::sync::OnceCell;

static GLOBAL_POOL: OnceCell<PgPool> = OnceCell::const_new();

pub async fn init_global_pool() -> &'static PgPool {
    GLOBAL_POOL
        .get_or_init(|| async {
            PgPool::connect("postgresql://postgres:PZNGfiJMJtPdPAugyDzfknXxjxEXyuER@metro.proxy.rlwy.net:30116/railway")
                .await
                .unwrap()
        })
        .await
}

pub fn get_global_pool() -> &'static PgPool {
    GLOBAL_POOL.get().expect("Pool not initialized")
}

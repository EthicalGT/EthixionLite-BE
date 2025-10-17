use sqlx::PgPool;
use tokio::sync::OnceCell;

static GLOBAL_POOL: OnceCell<PgPool> = OnceCell::const_new();

pub async fn init_global_pool() -> &'static PgPool {
    GLOBAL_POOL
        .get_or_init(|| async {
            PgPool::connect("postgresql://ethixion_r827_user:DOAmm6Y6P4FExB0lr0Tq9C7S74LQktop@dpg-d3p24t7diees73cbn890-a.ohio-postgres.render.com/ethixion_r827")
                .await
                .unwrap()
        })
        .await
}

pub fn get_global_pool() -> &'static PgPool {
    GLOBAL_POOL.get().expect("Pool not initialized")
}

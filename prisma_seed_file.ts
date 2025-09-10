import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Veritabanı seed işlemi başlıyor...');

  // Demo tenant oluştur
  const tenant = await prisma.tenant.upsert({
    where: { slug: 'demo-company' },
    update: {},
    create: {
      name: 'Demo Şirket A.Ş.',
      slug: 'demo-company',
      isActive: true,
    },
  });

  console.log('✅ Demo tenant oluşturuldu:', tenant.name);

  // Demo kullanıcıları oluştur
  const hashedPassword = await bcrypt.hash('123456', 12);

  const users = [
    {
      name: 'Ali Yılmaz',
      email: 'ali@demo.com',
      role: 'OWNER',
      password: hashedPassword,
      tenantId: tenant.id,
      department: 'Yönetim',
      position: 'İş Sahibi'
    },
    {
      name: 'Fatma Demir',
      email: 'fatma@demo.com',
      role: 'MANAGER',
      password: hashedPassword,
      tenantId: tenant.id,
      department: 'İnşaat',
      position: 'Proje Müdürü'
    },
    {
      name: 'Mehmet Kaya',
      email: 'mehmet@demo.com',
      role: 'LEAD',
      password: hashedPassword,
      tenantId: tenant.id,
      department: 'İnşaat',
      position: 'Şantiye Şefi'
    },
    {
      name: 'Ayşe Şahin',
      email: 'ayse@demo.com',
      role: 'WORKER',
      password: hashedPassword,
      tenantId: tenant.id,
      department: 'İnşaat',
      position: 'İşçi'
    },
    {
      name: 'Mustafa Öztürk',
      email: 'mustafa@demo.com',
      role: 'WORKER',
      password: hashedPassword,
      tenantId: tenant.id,
      department: 'Lojistik',
      position: 'Depo Sorumlusu'
    },
  ];

  for (const userData of users) {
    const user = await prisma.user.upsert({
      where: { 
        tenantId_email: { 
          tenantId: userData.tenantId, 
          email: userData.email 
        } 
      },
      update: {},
      create: userData,
    });
    console.log(`✅ Kullanıcı oluşturuldu: ${user.name} (${user.role})`);
  }

  // Demo görevleri oluştur
  const allUsers = await prisma.user.findMany({ where: { tenantId: tenant.id } });
  const owner = allUsers.find(u => u.role === 'OWNER');
  const manager = allUsers.find(u => u.role === 'MANAGER');
  const lead = allUsers.find(u => u.role === 'LEAD');
  const workers = allUsers.filter(u => u.role === 'WORKER');

  const tasks = [
    {
      title: 'Şantiye güvenlik raporu hazırlama',
      description: 'Haftalık güvenlik kontrolü yapılacak ve rapor hazırlanacak',
      priority: 'HIGH',
      status: 'OPEN',
      assignedById: owner!.id,
      assignedToId: manager!.id,
      tenantId: tenant.id,
      dueAt: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000),
      tags: ['güvenlik', 'rapor', 'haftalık']
    },
    {
      title: 'Malzeme sayımı ve envanter güncelleme',
      description: 'Depo malzemelerinin sayımı yapılacak',
      priority: 'MEDIUM',
      status: 'IN_PROGRESS',
      assignedById: manager!.id,
      assignedToId: lead!.id,
      tenantId: tenant.id,
      dueAt: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000),
      tags: ['envanter', 'sayım']
    },
    {
      title: 'Günlük temizlik kontrol',
      description: 'Çalışma alanlarının temizlik kontrolü',
      priority: 'LOW',
      status: 'DONE',
      assignedById: lead!.id,
      assignedToId: workers[0].id,
      tenantId: tenant.id,
      dueAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
      tags: ['temizlik', 'günlük']
    },
    {
      title: 'Haftalık toplantı hazırlığı',
      description: 'Pazartesi günkü haftalık değerlendirme toplantısı için sunum hazırlanacak',
      priority: 'URGENT',
      status: 'OPEN',
      assignedById: owner!.id,
      assignedToId: workers[1].id,
      tenantId: tenant.id,
      dueAt: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
      tags: ['toplantı', 'sunum']
    },
  ];

  for (const taskData of tasks) {
    const task = await prisma.task.create({ data: taskData });
    console.log(`✅ Görev oluşturuldu: ${task.title}`);
  }

  // Demo raporları oluştur
  const reports = [
    {
      title: 'Günlük Vardiya Raporu - A Ekibi',
      body: 'Bugün toplam 8 işçi ile çalışıldı. Ana yapı inşaatında %15 ilerleme sağlandı. Herhangi bir güvenlik problemi yaşanmadı.',
      category: 'SHIFT',
      createdById: workers[0].id,
      tenantId: tenant.id,
      tags: ['vardiya', 'günlük']
    },
    {
      title: 'Malzeme Teslimat Raporu',
      body: 'Çimento ve demir çubuğu teslimatı tamamlandı. Kalite kontrol geçti.',
      category: 'DELIVERY',
      createdById: lead!.id,
      tenantId: tenant.id,
      tags: ['teslimat', 'malzeme']
    },
    {
      title: 'Güvenlik Kontrol Raporu',
      body: 'Şantiye güvenlik ekipmanları kontrol edildi. Eksik bulunan kasklar tamamlandı.',
      category: 'INSPECTION',
      createdById: manager!.id,
      tenantId: tenant.id,
      tags: ['güvenlik', 'kontrol']
    },
  ];

  for (const reportData of reports) {
    const report = await prisma.report.create({ data: reportData });
    console.log(`✅ Rapor oluşturuldu: ${report.title}`);
  }

  // Demo chat oluştur
  const groupChat = await prisma.chat.create({
    data: {
      type: 'GROUP',
      name: 'Şantiye A Ekibi',
      description: 'Ana şantiye ekibi genel sohbet',
      tenantId: tenant.id,
      createdById: manager!.id,
    }
  });

  // Chat üyeleri ekle
  const chatMembers = [manager!.id, lead!.id, ...workers.map(w => w.id)];
  for (const userId of chatMembers) {
    await prisma.chatMember.create({
      data: {
        chatId: groupChat.id,
        userId,
        canMessage: true,
      }
    });
  }

  // Demo mesajlar
  const messages = [
    {
      chatId: groupChat.id,
      senderId: manager!.id,
      body: 'Günaydın ekip! Bugünkü hedeflerimizi gözden geçirelim.',
      createdAt: new Date(Date.now() - 3 * 60 * 60 * 1000)
    },
    {
      chatId: groupChat.id,
      senderId: lead!.id,
      body: 'Günaydın! Malzeme sayımı için hazırım.',
      createdAt: new Date(Date.now() - 2.5 * 60 * 60 * 1000)
    },
    {
      chatId: groupChat.id,
      senderId: workers[0].id,
      body: 'Temizlik işleri tamamlandı, raporu yükledim.',
      createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000)
    },
    {
      chatId: groupChat.id,
      senderId: manager!.id,
      body: 'Teşekkürler! Raporları kontrol ediyorum.',
      createdAt: new Date(Date.now() - 1.5 * 60 * 60 * 1000)
    },
  ];

  for (const messageData of messages) {
    await prisma.message.create({ data: messageData });
  }

  console.log('✅ Demo chat ve mesajlar oluşturuldu');

  console.log('🎉 Seed işlemi tamamlandı!');
  console.log('');
  console.log('📋 Demo Kullanıcılar:');
  console.log('   OWNER:   ali@demo.com     / 123456');
  console.log('   MANAGER: fatma@demo.com   / 123456');
  console.log('   LEAD:    mehmet@demo.com  / 123456');
  console.log('   WORKER:  ayse@demo.com    / 123456');
  console.log('   WORKER:  mustafa@demo.com / 123456');
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });